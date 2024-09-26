package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"

	// sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"

	// stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	// authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	// authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	tmtypes "github.com/tendermint/tendermint/types"

	// wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"

	appparams "github.com/confio/tgrade/app/params"
	"github.com/confio/tgrade/x/poe/contract"

	// poekeeper "github.com/confio/tgrade/x/poe/keeper"
	poetypes "github.com/confio/tgrade/x/poe/types"
	twasmtypes "github.com/confio/tgrade/x/twasm/types"
)

type DistributionContract struct {
	Address string `json:"contract"`
	// Ratio of total reward tokens for an epoch to be sent to that contract for further distribution.
	// Range 0 - 1
	Ratio string `json:"ratio"`
}

type ValSetConfig struct {
	AutoUnjail            bool                   `json:"auto_unjail"`
	DistributionContracts []DistributionContract `json:"distribution_contracts"`
	DoubleSignSlashRatio  string                 `json:"double_sign_slash_ratio"`
	EpochReward           sdk.Coin               `json:"epoch_reward"`
	FeePercentage         string                 `json:"fee_percentage"`
	MaxValidators         uint32                 `json:"max_validators"`
	Membership            string                 `json:"membership"`
	MinPoints             uint64                 `json:"min_points"`
	OfflineJailDuration   uint64                 `json:"offline_jail_duration"`
	Scaling               uint32                 `json:"scaling"`
	ValidatorGroup        string                 `json:"validator_group"`
	VerifyValidators      bool                   `json:"verify_validators"`
}

type ValSetContractVersion struct {
	Contract string `json:"contract"`
	Version  string `json:"version"`
}

type ValSetValidatorsStartHeight struct {
	Height    uint64 `json:"height"`
	Validator string `json:"validator"`
}

type Operator struct {
	Operator        string                     `json:"operator"`
	Pubkey          contract.ValidatorPubkey   `json:"pubkey"`
	Metadata        contract.ValidatorMetadata `json:"metadata"`
	JailedUntil     *JailingPeriod             `json:"jailed_until,omitempty"`
	ActiveValidator bool                       `json:"active_validator"`
}

type JailingEnd struct {
	Forever struct{} `json:"forever,omitempty"`
	Until   string   `json:"until,omitempty"`
}

type JailingPeriod struct {
	Start string     `json:"start,omitempty"`
	End   JailingEnd `json:"end,omitempty"`
}

type ListValidatorSlashingResponse struct {
	Validator string                       `json:"validator"`
	Slashing  []contract.ValidatorSlashing `json:"slashing"`
}

type ValSetMsg struct {
	Admin                 string                          `json:"admin"`
	Config                ValSetConfig                    `json:"config"`
	ContractVersion       ValSetContractVersion           `json:"contract_version"`
	Epoch                 contract.ValsetEpochResponse    `json:"epoch"`
	Operators             []Operator                      `json:"operators"`
	Validators            []contract.ValidatorInfo        `json:"validators"`
	ValidatorsSlashing    []ListValidatorSlashingResponse `json:"validators_slashing"`
	ValidatorsStartHeight []ValSetValidatorsStartHeight   `json:"validators_start_height"`
}

// MigrateGenesisWithValidatorSet returns cobra Command.
func MigrateGenesisWithValidatorSet(defaultNodeHome string, encodingConfig appparams.EncodingConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate-genesis-with-validatorset [genesis_file] [output_file] [hardfork_index] [validator_addresses_file]",
		Short: "Migrate an exported genesis with a modified validator set",
		Long: `Migrate an exported genesis with a modified validator set
`,
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)
			serverCtx := server.GetServerContextFromCmd(cmd)
			config := serverCtx.Config

			config.SetRoot(clientCtx.HomeDir)

			genesisFile := args[0]
			outputFile := args[1]
			hfindex, err := strconv.Atoi(args[2])
			if err != nil {
				return fmt.Errorf("failed to parse hardfork index: %s: %s", args[2], err.Error())
			}
			validatorsFile := args[3]
			file, err := os.ReadFile(validatorsFile)
			if err != nil {
				fmt.Println("Error reading validator file:", err)
				os.Exit(1)
			}
			var validators []string
			err = json.Unmarshal(file, &validators)
			if err != nil {
				fmt.Println("Error unmarshaling validators:", err)
				os.Exit(1)
			}

			appState, genDoc, err := genutiltypes.GenesisStateFromGenFile(genesisFile)
			if err != nil {
				return fmt.Errorf("failed to unmarshal genesis state: %w", err)
			}

			validatorMap := make(map[string]bool)
			for _, item := range validators {
				validatorMap[item] = true
			}

			appState, genDoc, err = MigrateValidatorState(clientCtx, appState, genDoc, int32(hfindex), validatorMap)
			if err != nil {
				return fmt.Errorf("migration failed: %w", err)
			}

			appStateJSON, err := json.Marshal(appState)
			if err != nil {
				return fmt.Errorf("failed to marshal application genesis state: %w", err)
			}

			genDoc.AppState = appStateJSON
			return genutil.ExportGenesisFile(genDoc, outputFile)
		},
	}

	cmd.Flags().String(flags.FlagHome, defaultNodeHome, "The application home directory")
	cmd.Flags().String(flags.FlagKeyringBackend, flags.DefaultKeyringBackend, "Select keyring's backend (os|file|kwallet|pass|test)")
	cmd.Flags().String(flagVestingAmt, "", "amount of coins for vesting accounts")
	cmd.Flags().Int64(flagVestingStart, 0, "schedule start time (unix epoch) for vesting accounts")
	cmd.Flags().Int64(flagVestingEnd, 0, "schedule end time (unix epoch) for vesting accounts")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// migrating validators follows logic from end_block per epoch recalculations https://github.com/confio/poe-contracts/blob/b7a8dbafd89cd70401dced518366f520b7089ff6/contracts/tgrade-valset/src/contract.rs#L709
func MigrateValidatorState(clientCtx client.Context, appState map[string]json.RawMessage, genDoc *tmtypes.GenesisDoc, hfversion int32, renewvalidators map[string]bool) (map[string]json.RawMessage, *tmtypes.GenesisDoc, error) {
	cdc := clientCtx.Codec
	fmt.Println("---genesis.ChainID--", genDoc.ChainID)

	// Modify the chain_id
	genDoc.ChainID = fmt.Sprintf("tgrade-mainnet-%d", hfversion)

	poegenesis := poetypes.GetGenesisStateFromAppState(cdc, appState)

	fmt.Println("---poegenesis--", poegenesis)

	contracts := poegenesis.GetImportDump()
	valSet := ""
	staking := ""
	for _, c := range contracts.Contracts {
		if c.ContractType == poetypes.PoEContractTypeValset {
			valSet = c.GetAddress()
		}
		if c.ContractType == poetypes.PoEContractTypeStaking {
			staking = c.GetAddress()
		}
	}

	var twasmGenesisState twasmtypes.GenesisState
	cdc.MustUnmarshalJSON(appState[twasmtypes.ModuleName], &twasmGenesisState)

	// get all contract addresses from poecontract
	genesisValidators := make([]tmtypes.GenesisValidator, 0)

	for wcindex, wcontract := range twasmGenesisState.Contracts {
		if wcontract.ContractInfo.Extension == nil {
			continue
		}
		// var ext twasmtypes.TgradeContractDetails
		// err := cdc.UnpackAny(contract.ContractInfo.Extension, &ext)
		// if err != nil {
		// 	continue
		// }
		// if ext.HasRegisteredPrivilege(twasmtypes.PrivilegeTypeValidatorSetUpdate) {
		if wcontract.ContractAddress == valSet {
			cmod := wcontract.GetCustomModel()
			if cmod == nil {
				return appState, genDoc, fmt.Errorf("ValSet contract does not have custom model")
			}
			fmt.Println("-PrivilegeTypeValidatorSetUpdate Msg-", string(cmod.Msg))
			// ValSetMsg
			// kvmodel := wcontract.GetKvModel()
			// if kvmodel != nil {
			// }
			var initMsg ValSetMsg
			err := json.Unmarshal(cmod.Msg, &initMsg)
			if err != nil {
				return appState, genDoc, err
			}
			fmt.Println("-PrivilegeTypeValidatorSetUpdate initMsg-", initMsg)
			// TODO how to recalculate power?

			for i, op := range initMsg.Operators {
				fmt.Println("--Operators--", op.Operator, renewvalidators[op.Operator])
				if ok := renewvalidators[op.Operator]; !ok {
					initMsg.Operators[i].ActiveValidator = false
					initMsg.Operators[i].JailedUntil = &JailingPeriod{
						// Start: time.Now(),
						Start: strconv.Itoa(int(time.Now().Unix() * 1000000)),
						End:   JailingEnd{Forever: struct{}{}},
					}
				}
			}
			newValidators := make([]contract.ValidatorInfo, 0)
			removedPow := uint64(0)
			for _, val := range initMsg.Validators {
				if ok := renewvalidators[val.Operator]; !ok {
					removedPow = removedPow + val.Power
					// TODO does this mean its slashed, or do I have to modify more storage?
					slashingInfo := contract.ValidatorSlashing{Height: uint64(genDoc.InitialHeight), Portion: sdk.OneDec()}
					found := false
					for is, slashval := range initMsg.ValidatorsSlashing {
						if slashval.Validator == val.Operator {
							found = true
							initMsg.ValidatorsSlashing[is].Slashing = append(initMsg.ValidatorsSlashing[is].Slashing, slashingInfo)
						}
					}
					if !found {
						slashing := ListValidatorSlashingResponse{
							Validator: val.Operator,
							Slashing:  []contract.ValidatorSlashing{slashingInfo},
						}
						initMsg.ValidatorsSlashing = append(initMsg.ValidatorsSlashing, slashing)
					}
				}
			}
			for _, val := range initMsg.Validators {
				fmt.Println("--Validators--", val.Operator, renewvalidators[val.Operator])
				// if ok := renewvalidators[val.Operator]; !ok {
				// 	initMsg.Validators[i].Power = 0 // TODO recalculate for everyone??
				// }
				if ok := renewvalidators[val.Operator]; ok {
					// TODO recalculate power
					// val.Power = uint64(initMsg.Config.Scaling) *
					// power: m.points * scaling,
					// poetypes.PoEContractTypeMixer
					val.Power = val.Power + removedPow // TODO fixme
					newValidators = append(newValidators, val)
					for _, genv := range genDoc.Validators {
						if bytes.Equal(genv.PubKey.Bytes(), val.ValidatorPubkey.Ed25519) {
							genv.Power = int64(val.Power)
							genesisValidators = append(genesisValidators, genv)
						}
					}
				}
			}
			initMsg.Validators = newValidators

			initMsgBz, err := json.Marshal(&initMsg)
			if err != nil {
				return appState, genDoc, err
			}
			cmod.Msg = initMsgBz
			// wcontract.SetCustomModel(initMsgBz);
			fmt.Println("-PrivilegeTypeValidatorSetUpdate new ValSet initmsg-", string(cmod.Msg))
		}
		if wcontract.ContractAddress == staking {
			// TODO
			fmt.Println("--hello staking--", wcontract)
			fmt.Println("--hello staking--", wcontract.ContractInfo.Label, wcontract.ContractInfo.Extension)
			fmt.Println("--hello ContractState--", wcontract.ContractInfo.Label, wcontract.ContractState)

			kvmodel := wcontract.GetKvModel()
			if kvmodel == nil {
				return appState, genDoc, fmt.Errorf("staking contract does not have kvmodel model")
			}

			unstaked := int64(0)
			unstakedPoints := int64(0)
			for modndx, mod := range kvmodel.Models {
				fmt.Println("---mod START--")
				fmt.Println("---staking mod key--", mod.Key, " ", string(mod.Key.Bytes()))
				fmt.Println("---staking mod value--", string(mod.Value), hex.EncodeToString(mod.Value))
				key := mod.Key.String()
				// "stake"
				if strings.HasPrefix(key, "00057374616B65") {
					addr := hexToBech32(strings.TrimPrefix(key, "00057374616B65"))
					value_ := strings.Trim(string(mod.Value), `"`)
					value, err := strconv.ParseInt(value_, 10, 64)
					if err != nil {
						return appState, genDoc, fmt.Errorf("staking contract: cannot parse stake value: %s", string(mod.Value))
					}
					unstaked += value
					if ok := renewvalidators[addr]; !ok {
						kvmodel.Models[modndx].Value = []byte(`"0"`)
					}
				}
				// "members"
				if strings.HasPrefix(key, "00076D656D62657273") {
					addr := hexToBech32(strings.TrimPrefix(key, "00076D656D62657273"))
					// {"points":700,"start_height":null}
					var points contract.TG4MemberResponse
					err := json.Unmarshal(mod.Value, &points)
					if err != nil {
						return appState, genDoc, fmt.Errorf("staking contract: cannot parse members value: %x", mod.Value)
					}
					if points.Points != nil {
						unstakedPoints += int64(*points.Points)
					}
					if ok := renewvalidators[addr]; !ok {
						kvmodel.Models[modndx].Value = []byte(`{"points":0,"start_height":null}`)
					}
				}
				// vesting_stake
				if strings.HasPrefix(key, "000D76657374696E675F7374616B65") {
					addr := hexToBech32(strings.TrimPrefix(key, "000D76657374696E675F7374616B65"))
					value_ := strings.Trim(string(mod.Value), `"`)
					value, err := strconv.ParseInt(value_, 10, 64)
					if err != nil {
						return appState, genDoc, fmt.Errorf("staking contract: cannot parse vesting stake value: %s", string(mod.Value))
					}
					unstaked += value
					if ok := renewvalidators[addr]; !ok {
						kvmodel.Models[modndx].Value = []byte(`"0"`)
					}
				}
				// members__point
				if strings.HasPrefix(key, "000F6D656D626572735F5F706F696E7473000800000000000002BC") {
					addr := hexToBech32(strings.TrimPrefix(key, "000F6D656D626572735F5F706F696E7473000800000000000002BC"))
					if ok := renewvalidators[addr]; !ok {
						kvmodel.Models[modndx].Value = []byte(`0`)
					}
				}
				// if strings.HasPrefix(key, "members__changelog-") {

				// }
				fmt.Println("---mod END--")
			}
			// update total staked
			// "total"
			for modndx, mod := range kvmodel.Models {
				if mod.Key.String() == "746F74616C" {
					value, err := strconv.ParseInt(string(mod.Value), 10, 64)
					if err != nil {
						return appState, genDoc, fmt.Errorf("staking contract: cannot parse value: %s", string(mod.Value))
					}
					value = value - unstakedPoints
					kvmodel.Models[modndx].Value = []byte(strconv.Itoa(int(value)))
				}
			}
		}

		twasmGenesisState.Contracts[wcindex] = wcontract

		bzz, err := wcontract.Marshal()
		fmt.Println("--wcontract--", err, string(bzz))
	}

	validatorsToRemove := map[string]bool{}

	fmt.Println("--validatorsToRemove--", validatorsToRemove)

	genDoc.Validators = genesisValidators

	// TODO either slashing or subtract stake?
	// TODO distribution fixes

	// burn stake for validatorsToRemove
	// TODO burn from supply?
	// TODO remove engagement from eliminated validators

	// TODO vesting accounts?
	// staked amount? who owns it?
	// validatorsToRemove addr => amount

	bankGenState := banktypes.GetGenesisStateFromAppState(cdc, appState)
	newBalances := make([]banktypes.Balance, 0)
	for _, b := range bankGenState.Balances {
		if ok := validatorsToRemove[b.Address]; !ok {
		}
	}
	bankGenState.Balances = newBalances

	// poegenesis.GetSeedContracts().ArbiterPoolMembers
	// poegenesis.GetSeedContracts().GenTxs
	// poegenesis.GetSeedContracts().OversightCommunityMembers = []string{"tgrade0"}
	// poegenesis.GetSeedContracts().ValsetContractConfig

	// change GenTx
	// burn other validator account TGD

	poetypes.SetGenesisStateInAppState(cdc, appState, poegenesis)
	appState[twasmtypes.ModuleName] = cdc.MustMarshalJSON(&twasmGenesisState)

	// fmt.Println("--NEW TWASM GENESIS STATE--", string(appState[twasmtypes.ModuleName]))

	return appState, genDoc, nil
}

func hexToBech32(value string) string {
	bz, err := hex.DecodeString(value)
	if err != nil {
		panic(fmt.Sprintf(`cannot convert hex to bech32: %s`, value))
	}
	return string(bz)
}

// func CreateUpgradeHandler(
// 	ak authkeeper.AccountKeeper,
// 	pk *poekeeper.Keeper,
// 	tk poetypes.TWasmKeeper,
// 	ctx sdk.Context,
// 	whitelist map[string]bool,
// ) error {
// 	// validators := pk.GetBondedValidatorsByPower(ctx)
// 	querier := poekeeper.NewQuerier(pk)
// 	fmt.Println("--CreateUpgradeHandler querier--", querier)
// 	// validators, err := querier.Validators(sdk.WrapSDKContext(ctx), &stakingtypes.QueryValidatorsRequest{})
// 	// fmt.Println("--CreateUpgradeHandler ValsetContract--", pk.ValsetContract(ctx))
// 	validators, _, err := pk.ValsetContract(ctx).ListValidators(ctx, nil)
// 	fmt.Println("-validators-", err, validators)
// 	if err != nil {
// 		return err
// 	}
// 	stakingContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeStaking)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("--stakingContractAddr--", stakingContractAddr)
// 	valsetContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeValset)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("--valsetContractAddr--", valsetContractAddr)
// 	adminContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunityGovProposals)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("--adminContractAddr--", adminContractAddr)
// 	oversightContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunity)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("--oversightContractAddr--", oversightContractAddr)

// 	for _, val := range validators {
// 		if _, ok := whitelist[val.OperatorAddress]; ok {
// 			fmt.Println("----is in whitelist---", val.OperatorAddress)
// 			continue
// 		}
// 		fmt.Println("----BURN!---", val.OperatorAddress)
// 		opaddr, err := sdk.AccAddressFromBech32(val.OperatorAddress)
// 		if err != nil {
// 			return fmt.Errorf("cannot convert bech32 to AccAddress: %s", val.OperatorAddress)
// 		}
// 		bondDenom := pk.GetBondDenom(ctx)
// 		// amount := sdk.Coin{Denom: poetypes.DefaultBondDenom, Amount: sdk.OneInt()}
// 		// sk.ValsetContract(ctx)

// 		amount, err := pk.StakeContract(ctx).QueryStakedAmount(ctx, opaddr)
// 		fmt.Println("--QueryStakedAmount--", err, amount)
// 		if err != nil || amount == nil {
// 			return fmt.Errorf("cannot query staked amount: %s", val.OperatorAddress)
// 		}
// 		unbondduration, err := pk.StakeContract(ctx).QueryStakingUnbondingPeriod(ctx)
// 		fmt.Println("--unbondduration--", err, unbondduration)

// 		bondedAmount := sdk.Coin{Denom: bondDenom, Amount: *amount}
// 		fmt.Println("--bondedAmount--", bondedAmount)

// 		// msg := contract.TG4StakeExecute{Unbond: &contract.Unbond{Tokens: wasmvmtypes.NewCoin(amount.Uint64(), bondDenom)}}
// 		fmt.Println("--sdk.OneDec()--", sdk.OneDec())
// 		msg := contract.TG4ValsetExecute{Slash: &contract.Slash{Addr: val.OperatorAddress, Portion: sdk.OneDec()}}
// 		msgBz, err := json.Marshal(msg)
// 		if err != nil {
// 			return sdkerrors.Wrap(err, "TG4StakeExecute message")
// 		}

// 		// ctx.WithEventManager(&em)
// 		if _, err = tk.GetContractKeeper().Execute(ctx, valsetContractAddr, adminContractAddr, msgBz, nil); err != nil {
// 			return sdkerrors.Wrap(err, "execute staking contract")
// 		}

// 		amount, err = pk.StakeContract(ctx).QueryStakedAmount(ctx, opaddr)
// 		fmt.Println("--QueryStakedAmount END--", err, amount)

// 		// also jail
// 		jailDuration := contract.JailingDuration{Forever: &struct{}{}}
// 		jailMsg := contract.TG4ValsetExecute{Jail: &contract.JailMsg{Operator: val.OperatorAddress, Duration: jailDuration}}
// 		jailMsgBz, err := json.Marshal(jailMsg)
// 		if err != nil {
// 			return sdkerrors.Wrap(err, "TG4StakeExecute message")
// 		}

// 		// ctx.WithEventManager(&em)
// 		if _, err = tk.GetContractKeeper().Execute(ctx, valsetContractAddr, adminContractAddr, jailMsgBz, nil); err != nil {
// 			return sdkerrors.Wrap(err, "execute staking contract")
// 		}

// 		// unbondTime, err := contract.UnbondDelegation(ctx, stakingContractAddr, opaddr, bondedAmount, tk.GetContractKeeper())
// 		// fmt.Println("--unbondTime--", err, unbondTime)
// 		// if err != nil {
// 		// 	return nil, err
// 		// }
// 	}

// 	validators, _, err = pk.ValsetContract(ctx).ListValidators(ctx, nil)
// 	// fmt.Println("-validators2-", err, validators)
// 	for _, val := range validators {
// 		fmt.Println("-validator2 final-", val.Status.String(), val.Jailed, val.IsUnbonded(), val.IsUnbonding(), val.BondedTokens())
// 		opaddr, err := sdk.AccAddressFromBech32(val.OperatorAddress)
// 		if err != nil {
// 			return fmt.Errorf("cannot convert bech32 to AccAddress: %s", val.OperatorAddress)
// 		}
// 		amount, err := pk.StakeContract(ctx).QueryStakedAmount(ctx, opaddr)
// 		fmt.Println("--QueryStakedAmount final--", val.OperatorAddress, err, amount)
// 		if err != nil {
// 			return fmt.Errorf("cannot query staked amount: %s", val.OperatorAddress)
// 		}
// 	}

// 	// disable oversight community contract
// 	newOcContractAddr := sdk.AccAddress{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
// 	pk.SetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunity, newOcContractAddr)

// 	return nil
// }

// func MigrateValidatorState(clientCtx client.Context, appState map[string]json.RawMessage, genDoc *tmtypes.GenesisDoc, hfversion int32, validators map[string]bool) (map[string]json.RawMessage, *tmtypes.GenesisDoc, error) {
// 	cdc := clientCtx.Codec
// 	fmt.Println("---genesis.ChainID--", genDoc.ChainID)

// 	// Modify the chain_id
// 	genDoc.ChainID = fmt.Sprintf("tgrade-mainnet-%d", hfversion)

// 	poegenesis := poetypes.GetGenesisStateFromAppState(cdc, appState)

// 	// fmt.Println("---poegenesis--", poegenesis)

// 	var twasmGenesisState twasmtypes.GenesisState
// 	cdc.MustUnmarshalJSON(appState[twasmtypes.ModuleName], &twasmGenesisState)

// 	// get all contract addresses from poecontract

// 	for _, contract := range twasmGenesisState.Contracts {
// 		if contract.ContractInfo.Extension == nil {
// 			continue
// 		}
// 		var ext twasmtypes.TgradeContractDetails
// 		err := cdc.UnpackAny(contract.ContractInfo.Extension, &ext)
// 		if err != nil {
// 			continue
// 		}
// 		if ext.HasRegisteredPrivilege(twasmtypes.PrivilegeTypeValidatorSetUpdate) {
// 			cmod := contract.GetCustomModel()
// 			if cmod != nil {
// 				fmt.Println("-PrivilegeTypeValidatorSetUpdate Msg-", string(cmod.Msg))
// 			}
// 			// kvmodel := contract.GetKvModel()
// 			// if kvmodel != nil {
// 			// }
// 		}
// 		if ext.HasRegisteredPrivilege(twasmtypes.Sta) {
// 		}
// 	}

// 	validatorsToRemove := map[string]bool{}

// 	fmt.Println("--validatorsToRemove--", validatorsToRemove)

// 	// TODO genDoc.Validators
// 	// burn stake for validatorsToRemove

// 	// TODO vesting accounts?
// 	// staked amount? who owns it?
// 	// validatorsToRemove addr => amount

// 	bankGenState := banktypes.GetGenesisStateFromAppState(cdc, appState)
// 	newBalances := make([]banktypes.Balance, 0)
// 	for _, b := range bankGenState.Balances {
// 		if ok := validatorsToRemove[b.Address]; !ok {
// 		}
// 	}
// 	bankGenState.Balances = newBalances

// 	// authGenState := authtypes.GetGenesisStateFromAppState(cdc, appState)
// 	// accs, err := authtypes.UnpackAccounts(authGenState.Accounts)
// 	// if err != nil {
// 	// 	return appState, genDoc, fmt.Errorf("failed to get accounts from any: %w", err)
// 	// }
// 	// newaccs := make(authtypes.GenesisAccounts, 0)
// 	// for _, acc := range accs {
// 	// 	if ok := validatorsToRemove[acc.GetAddress().String()]; ok {
// 	// 		acc.balan
// 	// 	}
// 	// }

// 	// poegenesis.GetSeedContracts().ArbiterPoolMembers
// 	// poegenesis.GetSeedContracts().GenTxs
// 	// poegenesis.GetSeedContracts().OversightCommunityMembers = []string{"tgrade0"}
// 	// poegenesis.GetSeedContracts().ValsetContractConfig

// 	// change GenTx
// 	// burn other validator account TGD

// 	poetypes.SetGenesisStateInAppState(cdc, appState, poegenesis)

// 	return appState, genDoc, nil
// }

// func MigrateValidatorState(clientCtx client.Context, appState map[string]json.RawMessage, genDoc *tmtypes.GenesisDoc, hfversion int32, validators map[string]bool) (map[string]json.RawMessage, *tmtypes.GenesisDoc, error) {
// 	cdc := clientCtx.Codec
// 	fmt.Println("---genesis.ChainID--", genDoc.ChainID)

// 	// Modify the chain_id
// 	genDoc.ChainID = fmt.Sprintf("tgrade-mainnet-%d", hfversion)

// 	poegenesis := poetypes.GetGenesisStateFromAppState(cdc, appState)

// 	// fmt.Println("---poegenesis--", poegenesis)

// 	// fmt.Println("---GetSeedContracts--", poegenesis.GetSeedContracts())

// 	genTxsBz := poegenesis.GetSeedContracts().GenTxs
// 	fmt.Println("---genTxsBz--", len(genTxsBz))

// 	newGenTxsBz := make([]json.RawMessage, 0)
// 	validatorsToRemove := map[string]bool{}

// 	for _, genTxBz := range genTxsBz {
// 		tx, err := clientCtx.TxConfig.TxJSONDecoder()(genTxBz)
// 		if err != nil {
// 			return appState, genDoc, err
// 		}

// 		msgs := tx.GetMsgs()
// 		if len(msgs) == 0 {
// 			return appState, genDoc, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid gentx")
// 		}

// 		msg, ok := msgs[0].(*stakingtypes.MsgCreateValidator)
// 		if !ok {
// 			return appState, genDoc, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "could not decode MsgCreateValidator")
// 		}
// 		validatorAddress := msg.ValidatorAddress

// 		// sigTx, ok := tx.(authsigning.Tx)
// 		// if !ok {
// 		// 	return appState, genDoc, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
// 		// }
// 		// signers := sigTx.GetSigners()
// 		// if len(signers) == 0 {
// 		// 	return appState, genDoc, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "invalid number of signer;  expected: 1, got %d", len(signers))
// 		// }
// 		// validatorAddress := signers[0].String()

// 		if ok := validators[validatorAddress]; !ok {
// 			validatorsToRemove[validatorAddress] = true
// 			continue
// 		}
// 		newGenTxsBz = append(newGenTxsBz, genTxBz)
// 	}

// 	poegenesis.GetSeedContracts().GenTxs = newGenTxsBz
// 	fmt.Println("--validatorsToRemove--", validatorsToRemove)
// 	fmt.Println("--newGenTxsBz--", len(newGenTxsBz))

// 	// TODO genDoc.Validators
// 	// burn stake for validatorsToRemove

// 	// TODO vesting accounts?
// 	// staked amount? who owns it?
// 	// validatorsToRemove addr => amount

// 	bankGenState := banktypes.GetGenesisStateFromAppState(cdc, appState)
// 	newBalances := make([]banktypes.Balance, 0)
// 	for _, b := range bankGenState.Balances {
// 		if ok := validatorsToRemove[b.Address]; !ok {
// 		}
// 	}
// 	bankGenState.Balances = newBalances

// 	// authGenState := authtypes.GetGenesisStateFromAppState(cdc, appState)
// 	// accs, err := authtypes.UnpackAccounts(authGenState.Accounts)
// 	// if err != nil {
// 	// 	return appState, genDoc, fmt.Errorf("failed to get accounts from any: %w", err)
// 	// }
// 	// newaccs := make(authtypes.GenesisAccounts, 0)
// 	// for _, acc := range accs {
// 	// 	if ok := validatorsToRemove[acc.GetAddress().String()]; ok {
// 	// 		acc.balan
// 	// 	}
// 	// }

// 	// poegenesis.GetSeedContracts().ArbiterPoolMembers
// 	// poegenesis.GetSeedContracts().GenTxs
// 	// poegenesis.GetSeedContracts().OversightCommunityMembers = []string{"tgrade0"}
// 	// poegenesis.GetSeedContracts().ValsetContractConfig

// 	// change GenTx
// 	// burn other validator account TGD

// 	poetypes.SetGenesisStateInAppState(cdc, appState, poegenesis)

// 	return appState, genDoc, nil
// }

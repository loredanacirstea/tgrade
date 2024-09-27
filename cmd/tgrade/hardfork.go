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

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"

	tmtypes "github.com/tendermint/tendermint/types"

	appparams "github.com/confio/tgrade/app/params"
	"github.com/confio/tgrade/x/poe/contract"
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

// {"denom":"utgd","tokens_per_point":"1000000","min_bond":"1","unbonding_period":1814400,"auto_return_limit":20}
type StakingConfig struct {
	Denom           string  `json:"denom"`
	TokensPerPoint  sdk.Int `json:"tokens_per_point,string"`
	MinBond         sdk.Int `json:"min_bond,string"`
	UnbondingPeriod uint64  `json:"unbonding_period"`
	AutoReturnLimit *uint64 `json:"auto_return_limit,omitempty"`
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

	// Modify the chain_id
	genDoc.ChainID = fmt.Sprintf("tgrade-mainnet-%d", hfversion)

	poegenesis := poetypes.GetGenesisStateFromAppState(cdc, appState)

	fmt.Println("* new ChainID:", genDoc.ChainID)
	fmt.Println("* start block height:", genDoc.InitialHeight)

	contracts := poegenesis.GetImportDump()
	valSet := ""
	stakingContractAddress := ""
	for _, c := range contracts.Contracts {
		if c.ContractType == poetypes.PoEContractTypeValset {
			valSet = c.GetAddress()
		}
		if c.ContractType == poetypes.PoEContractTypeStaking {
			stakingContractAddress = c.GetAddress()
		}
	}

	var twasmGenesisState twasmtypes.GenesisState
	cdc.MustUnmarshalJSON(appState[twasmtypes.ModuleName], &twasmGenesisState)

	// get all contract addresses from poecontract
	genesisValidators := make([]tmtypes.GenesisValidator, 0)
	unstaked := sdk.NewInt(0)
	stakeDenom := ""

	for wcindex, wcontract := range twasmGenesisState.Contracts {
		if wcontract.ContractInfo.Extension == nil {
			continue
		}
		if wcontract.ContractAddress == valSet {
			removedPow := uint64(0)
			cmod := wcontract.GetCustomModel()
			if cmod == nil {
				return appState, genDoc, fmt.Errorf("ValSet contract does not have custom model")
			}
			var initMsg ValSetMsg
			err := json.Unmarshal(cmod.Msg, &initMsg)
			if err != nil {
				return appState, genDoc, err
			}
			fmt.Printf("total operators: %d \n", len(initMsg.Operators))
			for i, op := range initMsg.Operators {
				if ok := renewvalidators[op.Operator]; !ok {
					initMsg.Operators[i].ActiveValidator = false
					initMsg.Operators[i].JailedUntil = &JailingPeriod{
						Start: strconv.Itoa(int(time.Now().Unix() * 1000000)),
						End:   JailingEnd{Forever: struct{}{}},
					}
				}
			}
			fmt.Printf("initial validators: %d \n", len(initMsg.Validators))
			newValidators := make([]contract.ValidatorInfo, 0)
			for _, val := range initMsg.Validators {
				if ok := renewvalidators[val.Operator]; !ok {
					removedPow = removedPow + val.Power
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
				if ok := renewvalidators[val.Operator]; ok {
					// power: m.points * scaling,
					// points are from ValSet.membership contract of type poetypes.PoEContractTypeMixer
					// this contract is the "poe" contract
					// val.Power = uint64(initMsg.Config.Scaling) * poePoints
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
			fmt.Printf("final validators: %d \n", len(initMsg.Validators))

			initMsgBz, err := json.Marshal(&initMsg)
			if err != nil {
				return appState, genDoc, err
			}
			cmod.Msg = initMsgBz
			fmt.Printf("* removedPow: %d \n", removedPow)
		}
		if wcontract.ContractAddress == stakingContractAddress {
			kvmodel := wcontract.GetKvModel()
			if kvmodel == nil {
				return appState, genDoc, fmt.Errorf("staking contract does not have kvmodel model")
			}

			unstakedPoints := int64(0)
			unstakedCount := 0
			for modndx, mod := range kvmodel.Models {
				// fmt.Println("---mod START--")
				// fmt.Println("---staking mod key--", mod.Key, " ", string(mod.Key.Bytes()))
				// fmt.Println("---staking mod value--", string(mod.Value), hex.EncodeToString(mod.Value))
				key := mod.Key.String()
				// config
				if key == "636F6E666967" {
					var config StakingConfig
					err := json.Unmarshal(mod.Value, &config)
					if err != nil {
						return appState, genDoc, fmt.Errorf("staking contract: cannot unmarshal config: %x: %s", mod.Value, err.Error())
					}
					stakeDenom = config.Denom
				}
				// "stake"
				if strings.HasPrefix(key, "00057374616B65") {
					addr := hexToBech32(strings.TrimPrefix(key, "00057374616B65"))
					if ok := renewvalidators[addr]; !ok {
						kvmodel.Models[modndx].Value = []byte(`"0"`)
						value_ := strings.Trim(string(mod.Value), `"`)
						value, ok := sdk.NewIntFromString(value_)
						if !ok {
							return appState, genDoc, fmt.Errorf("staking contract: cannot parse stake value: %s", string(mod.Value))
						}
						unstaked = unstaked.Add(value)
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
					if ok := renewvalidators[addr]; !ok {
						kvmodel.Models[modndx].Value = []byte(`{"points":0,"start_height":null}`)
						unstakedCount += 1
						if points.Points != nil {
							unstakedPoints += int64(*points.Points)
						}
					}
				}
				// vesting_stake
				if strings.HasPrefix(key, "000D76657374696E675F7374616B65") {
					addr := hexToBech32(strings.TrimPrefix(key, "000D76657374696E675F7374616B65"))
					if ok := renewvalidators[addr]; !ok {
						kvmodel.Models[modndx].Value = []byte(`"0"`)
						value_ := strings.Trim(string(mod.Value), `"`)
						value, ok := sdk.NewIntFromString(value_)
						if !ok {
							return appState, genDoc, fmt.Errorf("staking contract: cannot parse vesting stake value: %s", string(mod.Value))
						}
						unstaked = unstaked.Add(value)
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
					fmt.Printf("* unstaked counter: %d \n", unstakedCount)
					fmt.Printf("* unstakedPoints: %d \n", unstakedPoints)
					fmt.Printf("* remaining staked points: %d \n", value)
					kvmodel.Models[modndx].Value = []byte(strconv.Itoa(int(value)))
				}
			}
		}

		twasmGenesisState.Contracts[wcindex] = wcontract
	}

	genDoc.Validators = genesisValidators

	// burn unstaked
	unstakedCoins := sdk.NewCoins(sdk.NewCoin(stakeDenom, unstaked))
	fmt.Printf("* unstakedCoins: %s \n", unstakedCoins.String())
	bankGenState := banktypes.GetGenesisStateFromAppState(cdc, appState)
	bankGenState.Supply = bankGenState.Supply.Sub(unstakedCoins)

	// see logic from TgradeHandler.handleDelegate - we need to subtract staker contract balance
	for i, b := range bankGenState.Balances {
		if b.Address == stakingContractAddress {
			if unstakedCoins.IsAnyGT(b.Coins) {
				return appState, genDoc, fmt.Errorf("unstaked coins greater than staked balance: %s - %s", unstakedCoins.String(), b.Coins.String())
			}
			bankGenState.Balances[i].Coins = b.Coins.Sub(unstakedCoins)
			fmt.Printf("* remaining staked coins: %s - %s \n", bankGenState.Balances[i].Coins.String(), stakingContractAddress)
		}
	}

	// TODO slash the liquid and vesting claims ?
	// let (liquid_claims_slashed, vesting_claims_slashed) =

	// TODO distribution fixes
	// TODO remove engagement from eliminated validators - poe MIXER points
	// TODO vesting accounts?
	// Update membership messages
	// MemberChangedHookMsg

	// poegenesis.GetSeedContracts().ArbiterPoolMembers
	// poegenesis.GetSeedContracts().OversightCommunityMembers = []string{"tgrade0"}
	// poegenesis.GetSeedContracts().ValsetContractConfig

	poetypes.SetGenesisStateInAppState(cdc, appState, poegenesis)
	appState[twasmtypes.ModuleName] = cdc.MustMarshalJSON(&twasmGenesisState)
	appState[banktypes.ModuleName] = cdc.MustMarshalJSON(bankGenState)
	return appState, genDoc, nil
}

func hexToBech32(value string) string {
	bz, err := hex.DecodeString(value)
	if err != nil {
		panic(fmt.Sprintf(`cannot convert hex to bech32: %s`, value))
	}
	return string(bz)
}

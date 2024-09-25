package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	tmtypes "github.com/tendermint/tendermint/types"

	appparams "github.com/confio/tgrade/app/params"
	poetypes "github.com/confio/tgrade/x/poe/types"
)

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

func MigrateValidatorState(clientCtx client.Context, appState map[string]json.RawMessage, genDoc *tmtypes.GenesisDoc, hfversion int32, validators map[string]bool) (map[string]json.RawMessage, *tmtypes.GenesisDoc, error) {
	cdc := clientCtx.Codec
	fmt.Println("---genesis.ChainID--", genDoc.ChainID)

	// Modify the chain_id
	genDoc.ChainID = fmt.Sprintf("tgrade-mainnet-%d", hfversion)

	poegenesis := poetypes.GetGenesisStateFromAppState(cdc, appState)

	// fmt.Println("---poegenesis--", poegenesis)

	// fmt.Println("---GetSeedContracts--", poegenesis.GetSeedContracts())

	genTxsBz := poegenesis.GetSeedContracts().GenTxs
	fmt.Println("---genTxsBz--", len(genTxsBz))

	newGenTxsBz := make([]json.RawMessage, 0)
	validatorsToRemove := make([]string, 0)

	for _, genTxBz := range genTxsBz {
		tx, err := clientCtx.TxConfig.TxJSONDecoder()(genTxBz)
		if err != nil {
			return appState, genDoc, err
		}

		msgs := tx.GetMsgs()
		if len(msgs) == 0 {
			return appState, genDoc, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid gentx")
		}

		msg, ok := msgs[0].(*stakingtypes.MsgCreateValidator)
		if !ok {
			return appState, genDoc, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "could not decode MsgCreateValidator")
		}
		validatorAddress := msg.ValidatorAddress

		// sigTx, ok := tx.(authsigning.Tx)
		// if !ok {
		// 	return appState, genDoc, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
		// }
		// signers := sigTx.GetSigners()
		// if len(signers) == 0 {
		// 	return appState, genDoc, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "invalid number of signer;  expected: 1, got %d", len(signers))
		// }
		// validatorAddress := signers[0].String()

		if ok := validators[validatorAddress]; !ok {
			validatorsToRemove = append(validatorsToRemove, validatorAddress)
			continue
		}
		newGenTxsBz = append(newGenTxsBz, genTxBz)
	}

	poegenesis.GetSeedContracts().GenTxs = newGenTxsBz
	fmt.Println("--validatorsToRemove--", validatorsToRemove)
	fmt.Println("--newGenTxsBz--", len(newGenTxsBz))

	// TODO genDoc.Validators
	// burn stake for validatorsToRemove

	// poegenesis.GetSeedContracts().ArbiterPoolMembers
	// poegenesis.GetSeedContracts().GenTxs
	// poegenesis.GetSeedContracts().OversightCommunityMembers = []string{"tgrade0"}
	// poegenesis.GetSeedContracts().ValsetContractConfig

	// change GenTx
	// burn other validator account TGD

	poetypes.SetGenesisStateInAppState(cdc, appState, poegenesis)

	return appState, genDoc, nil
}

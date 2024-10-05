package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/server"

	poetypes "github.com/confio/tgrade/x/poe/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	authvesting "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	tmtypes "github.com/tendermint/tendermint/types"

	appparams "github.com/confio/tgrade/app/params"
)

var (
	analysisBalanceThresholdFlag = "balance-threshold"
	outputFileFlag               = "output-file"
)

// AnalyzeGenesisBalances returns cobra Command.
func AnalyzeGenesisBalances(defaultNodeHome string, encodingConfig appparams.EncodingConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze-genesis-balances [genesis_file] ",
		Short: "Analyze genesis balances.",
		Long: fmt.Sprintf(`Analyze genesis balances.
E.g. %s analyze-genesis-balances ./genesis_state_export.json --balance-threshold 1000000000000utgd --output-file="./balances.csv"
`, defaultNodeHome),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx := client.GetClientContextFromCmd(cmd)
			serverCtx := server.GetServerContextFromCmd(cmd)
			config := serverCtx.Config

			config.SetRoot(clientCtx.HomeDir)

			genesisFile := args[0]

			balanceThreshold, _ := cmd.Flags().GetString(analysisBalanceThresholdFlag) //nolint:errcheck
			outputFile, _ := cmd.Flags().GetString(outputFileFlag)                     //nolint:errcheck
			threshold, err := sdk.ParseCoinsNormalized(balanceThreshold)
			if err != nil {
				return err
			}

			appState, genDoc, err := genutiltypes.GenesisStateFromGenFile(genesisFile)
			if err != nil {
				return fmt.Errorf("failed to unmarshal genesis state: %w", err)
			}

			modnames := []string{
				banktypes.ModuleName,
				authtypes.ModuleName,
				authvesting.ModuleName,
				stakingtypes.ModuleName,
				govtypes.ModuleName,
				poetypes.ModuleName,
			}
			for _, modname := range modnames {
				fmt.Printf("%s : %s \n", modname, authtypes.NewModuleAddress(modname).String())
			}

			poegenesis := poetypes.GetGenesisStateFromAppState(clientCtx.Codec, appState)
			contracts := poegenesis.GetImportDump()
			for _, c := range contracts.Contracts {
				fmt.Printf("%s : %s \n", c.ContractType, c.GetAddress())
			}

			_, err = AnalyzeVesting(clientCtx, appState, genDoc)
			if err != nil {
				return err
			}

			output, err := SortBalancesUntilThreshold(clientCtx, appState, genDoc, threshold)
			if err != nil {
				return fmt.Errorf("analysis failed: %w", err)
			}
			if outputFile == "" {
				fmt.Printf("%s", output)
			} else {
				err = os.WriteFile(outputFile, []byte(output), 0o600)
				if err != nil {
					return nil
				}
			}

			return nil
		},
	}

	cmd.Flags().String(flags.FlagHome, defaultNodeHome, "The application home directory")
	cmd.Flags().String(analysisBalanceThresholdFlag, "", "minimum balance threshold")
	cmd.Flags().String(outputFileFlag, "", "output file path")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

func SortBalancesUntilThreshold(clientCtx client.Context, appState map[string]json.RawMessage, genDoc *tmtypes.GenesisDoc, threshold sdk.Coins) (string, error) {
	cdc := clientCtx.Codec
	fmt.Println("* new ChainID:", genDoc.ChainID)

	bankGenState := banktypes.GetGenesisStateFromAppState(cdc, appState)
	fmt.Printf("* bank supplies : \n")
	for _, coin := range bankGenState.Supply {
		fmt.Printf("%s %s \n", coin.Amount.String(), coin.Denom)
	}
	fmt.Printf("* balance threshold : %s \n", threshold.String())
	fmt.Printf("* total accounts with balance: %d \n", len(bankGenState.Balances))

	balancesContracts := make([]banktypes.Balance, 0)
	balancesAccounts := make([]banktypes.Balance, 0)
	for _, balance := range bankGenState.Balances {
		if balance.Coins.IsAllGTE(threshold) {
			if len(balance.Address) > 45 {
				balancesContracts = append(balancesContracts, balance)
			} else {
				balancesAccounts = append(balancesAccounts, balance)
			}
		}
	}

	sort.Slice(balancesContracts, func(i, j int) bool {
		return balancesContracts[i].Coins.IsAllGT(balancesContracts[j].Coins)
	})
	sort.Slice(balancesAccounts, func(i, j int) bool {
		return balancesAccounts[i].Coins.IsAllGT(balancesAccounts[j].Coins)
	})

	fmt.Printf("* contracts over threshold : %d \n", len(balancesContracts))
	fmt.Printf("* accounts over threshold : %d \n", len(balancesAccounts))
	output := "address"
	denoms := make([]string, 0)
	for _, coin := range threshold {
		output += "," + coin.Denom
		denoms = append(denoms, coin.Denom)
	}
	output += "\n"
	output = addBalanceCsvRows(balancesContracts, denoms, output)
	output = addBalanceCsvRows(balancesAccounts, denoms, output)
	return output, nil
}

func AnalyzeVesting(clientCtx client.Context, appState map[string]json.RawMessage, genDoc *tmtypes.GenesisDoc) (string, error) {
	cdc := clientCtx.Codec
	authGenState := authtypes.GetGenesisStateFromAppState(cdc, appState)

	accs, err := authtypes.UnpackAccounts(authGenState.Accounts)
	if err != nil {
		return "", err
	}
	vestingaccs := make([]*authvesting.BaseVestingAccount, 0)
	for _, acc := range accs {
		vestingacc, ok := acc.(*authvesting.BaseVestingAccount)
		if ok {
			vestingaccs = append(vestingaccs, vestingacc)
		}
	}
	fmt.Println("* vesting accounts: ", len(vestingaccs))
	// for _, acc := range vestingaccs {
	// 	fmt.Println("* vesting ", vestingacc)
	// }

	output := ""
	return output, nil
}

func addBalanceCsvRows(balances []banktypes.Balance, denoms []string, output string) string {
	for _, balance := range balances {
		output += balance.Address
		for _, coin := range balance.Coins {
			if slices.Contains(denoms, coin.Denom) {
				output += "," + coin.Amount.String()
			}
		}
		output += "\n"
	}
	return output
}

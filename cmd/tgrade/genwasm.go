package main

import (
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/spf13/cobra"
)

func GenesisWasmFlagsCmd(defaultNodeHome string) *cobra.Command {
	txCmd := &cobra.Command{
		Use:                        "wasm-genesis-flags",
		Short:                      "Wasm genesis flag subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	return txCmd
}

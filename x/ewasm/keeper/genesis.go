package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/confio/tgrade/x/ewasm/types"
)

// InitGenesis initializes the ewasm module's state from a provided genesis
// state.
func (k Keeper) InitGenesis(ctx sdk.Context, data types.GenesisState) {
	k.SetParams(ctx, data.Params)
}

// ExportGenesis returns the ewasm module's exported genesis.
func (k Keeper) ExportGenesis(ctx sdk.Context) *types.GenesisState {
	return &types.GenesisState{
		Params: k.GetParams(ctx),
	}
}

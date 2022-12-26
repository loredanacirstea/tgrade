package keeper

import (
	// "context"
	// "errors"
	// "fmt"

	// sdk "github.com/cosmos/cosmos-sdk/types"
	// abci "github.com/tendermint/tendermint/abci/types"

	// cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	// sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	// icatypes "github.com/cosmos/ibc-go/v4/modules/apps/27-interchain-accounts/types"

	"github.com/confio/tgrade/x/ewasm/types"
)

var _ types.MsgServer = &Keeper{}

// // SubmitCosmosTx implements the Msg/SubmitCosmosTx interface
// func (k Keeper) SubmitCosmosTx(goCtx context.Context, msg *types.MsgSubmitCosmosTx) (*types.MsgSubmitCosmosTxResponse, error) {

// }

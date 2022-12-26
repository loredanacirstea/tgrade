package types

import (
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	ErrInternalEwasm = sdkerrors.Register(ModuleName, 3, "internal ewasm error")
	ErrEwasmDisabled = sdkerrors.Register(ModuleName, 4, "module disabled")
)

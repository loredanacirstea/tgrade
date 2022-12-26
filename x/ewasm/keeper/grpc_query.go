package keeper

import (
	"github.com/confio/tgrade/x/ewasm/types"
)

var _ types.QueryServer = Keeper{}

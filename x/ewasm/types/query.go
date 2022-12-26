package types

import (
	"github.com/cosmos/gogoproto/proto"
)

type Query interface {
	proto.Message
}

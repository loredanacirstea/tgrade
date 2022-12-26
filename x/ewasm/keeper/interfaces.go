package keeper

import (
	"github.com/tendermint/tendermint/libs/log"

	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	// poekeeper "github.com/confio/tgrade/x/poe/keeper"
	// poetypes "github.com/confio/tgrade/x/poe/types"
	twasmtypes "github.com/confio/tgrade/x/twasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// type PoeKeeper interface {
// 	DeleteHistoricalInfo(ctx sdk.Context, height int64)
// 	DistributionContract(ctx sdk.Context) poekeeper.DistributionContract
// 	EngagementContract(ctx sdk.Context) poekeeper.EngagementContract
// 	GetBondDenom(ctx sdk.Context) string
// 	GetEngagementPoints(ctx sdk.Context, opAddr sdk.AccAddress) (uint64, error)
// 	// GetHistoricalInfo(ctx sdk.Context, height int64) (poetypes.HistoricalInfo, bool)
// 	GetInitialValidatorEngagementPoints(ctx sdk.Context) (res uint64)
// 	GetParams(ctx sdk.Context) poetypes.Params
// 	GetPoEContractAddress(ctx sdk.Context, ctype poetypes.PoEContractType) (sdk.AccAddress, error)
// 	// GetValidatorVotes() []poetypes.VoteInfo
// 	HistoricalEntries(ctx sdk.Context) (res uint32)
// 	InitContractAddressCache(ctx sdk.Context)
// 	IteratePoEContracts(ctx sdk.Context, cb func(poetypes.PoEContractType, sdk.AccAddress) bool)
// 	MinimumDelegationAmounts(ctx sdk.Context) (res sdk.Coins)
// 	// SetHistoricalInfo(ctx sdk.Context, height int64, hi *poetypes.HistoricalInfo)
// 	SetPoEContractAddress(ctx sdk.Context, ctype poetypes.PoEContractType, contractAddr sdk.AccAddress)
// 	SetValidatorInitialEngagementPoints(ctx sdk.Context, opAddr sdk.AccAddress, selfDelegation sdk.Coin) error
// 	StakeContract(ctx sdk.Context) poekeeper.StakeContract
// 	TrackHistoricalInfo(ctx sdk.Context)
// 	UnbondingTime(ctx sdk.Context) time.Duration
// 	// UpdateValidatorVotes(validatorVotes []poetypes.VoteInfo)
// 	ValsetContract(ctx sdk.Context) poekeeper.ValsetContract
// }

type TwasmKeeper interface {
	ExistsAnyPrivilegedContract(ctx sdk.Context, privilegeType twasmtypes.PrivilegeType) bool
	GetContractKeeper() wasmtypes.ContractOpsKeeper
	HasPrivilegedContract(ctx sdk.Context, contractAddr sdk.AccAddress, privilegeType twasmtypes.PrivilegeType) (bool, error)
	IsPrivileged(ctx sdk.Context, contractAddr sdk.AccAddress) bool
	IteratePrivileged(ctx sdk.Context, cb func(sdk.AccAddress) bool)
	IteratePrivilegedContractsByType(ctx sdk.Context, privilegeType twasmtypes.PrivilegeType, cb func(prio uint8, contractAddr sdk.AccAddress) bool)
	Logger(ctx sdk.Context) log.Logger
	SetPrivileged(ctx sdk.Context, contractAddr sdk.AccAddress) error
	UnsetPrivileged(ctx sdk.Context, contractAddr sdk.AccAddress) error
}

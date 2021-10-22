package contract

import (
	"encoding/json"
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptosecp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"

	"github.com/confio/tgrade/x/poe/types"
)

func DecimalFromPercentage(percent sdk.Dec) *sdk.Dec {
	if percent.IsZero() {
		return nil
	}
	res := percent.QuoInt64(100)
	return &res
}

func DecimalFromProMille(promille int64) *sdk.Dec {
	res := sdk.NewDec(promille).QuoInt64(1000)
	return &res
}

// ValsetInitMsg Valset contract init message
// See https://github.com/confio/tgrade-contracts/tree/v0.5.0-alpha/contracts/tgrade-valset/src/msg.rs
type ValsetInitMsg struct {
	Admin         string      `json:"admin,omitempty"`
	Membership    string      `json:"membership"`
	MinWeight     uint64      `json:"min_weight"`
	MaxValidators uint32      `json:"max_validators"`
	EpochLength   uint64      `json:"epoch_length"`
	EpochReward   sdk.Coin    `json:"epoch_reward"`
	InitialKeys   []Validator `json:"initial_keys"`
	Scaling       uint32      `json:"scaling,omitempty"`
	// Percentage of total accumulated fees which is substracted from tokens minted as a rewards. A fixed-point decimal value with 18 fractional digits, i.e. Decimal(1_000_000_000_000_000_000) == 1.0
	FeePercentage *sdk.Dec `json:"fee_percentage,string,omitempty"`
	// If set to true, we will auto-unjail any validator after their jailtime is over.
	AutoUnjail bool `json:"auto_unjail"`
	// What percentage of the rewards (fees + inflation) go to validators. The rest go to distribution contract (below)
	ValidatorsRewardRatio *sdk.Dec `json:"validators_reward_ratio,string,omitempty"`
	// This contract receives the rewards that don't go to the validator (set ot tg4-engagement)
	DistributionContract string `json:"distribution_contract,omitempty"`
	// This is the code-id of the cw2222-compliant contract used to handle rewards for the validators
	// Generally should the the tg4-engagement code id
	RewardsCodeId uint64 `json:"rewards_code_id"`
}

func (m ValsetInitMsg) Json(t *testing.T) string {
	return asJson(t, m)
}

type Validator struct {
	Operator        string          `json:"operator"`
	ValidatorPubkey ValidatorPubkey `json:"validator_pubkey"`
}

func asJson(t *testing.T, m interface{}) string {
	t.Helper()
	r, err := json.Marshal(&m)
	require.NoError(t, err)
	return string(r)
}

// TG4ValsetExecute Valset contract validator key registration
// See https://github.com/confio/tgrade-contracts/tree/v0.5.0-alpha/contracts/tgrade-valset/src/msg.rs
type TG4ValsetExecute struct {
	RegisterValidatorKey *RegisterValidatorKey `json:"register_validator_key,omitempty"`
	UpdateMetadata       *ValidatorMetadata    `json:"update_metadata,omitempty"`
	// Jails validator. Can be executed only by the admin.
	Jail *JailMsg `json:"jail,omitempty"`
	// Unjails validator. Admin can unjail anyone anytime, others can unjail only themselves and
	// only if the jail period passed.
	Unjail *UnjailMsg `json:"unjail,omitempty"`
}

type JailMsg struct {
	Operator string `json:"operator"`
	// Duration for how long validator is jailed (in seconds)
	// 0 means jailing forever
	Duration uint64 `json:"duration,omitempty"`
}

type UnjailMsg struct {
	// Address to unjail. Optional, as if not provided it is assumed to be the sender of the
	// message (for convenience when unjailing self after the jail period).
	Operator string `json:"operator,omitempty"`
}

type RegisterValidatorKey struct {
	PubKey   ValidatorPubkey   `json:"pubkey"`
	Metadata ValidatorMetadata `json:"metadata"`
}

type ValidatorMetadata struct {
	// moniker defines a human-readable name for the validator.
	Moniker string `json:"moniker"`
	// identity defines an optional identity signature (ex. UPort or Keybase).
	Identity string `json:"identity,omitempty"`
	// website defines an optional website link.
	Website string `json:"website,omitempty"`
	// security_contact defines an optional email for security contact.
	SecurityContact string `json:"security_contact,omitempty"`
	// details define other optional details.
	Details string `json:"details,omitempty"`
}

func MetadataFromDescription(description stakingtypes.Description) ValidatorMetadata {
	return ValidatorMetadata{
		Moniker:         description.Moniker,
		Identity:        description.Identity,
		Website:         description.Website,
		SecurityContact: description.SecurityContact,
		Details:         description.Details,
	}
}

func (m ValidatorMetadata) ToDescription() stakingtypes.Description {
	return stakingtypes.Description{
		Moniker:         m.Moniker,
		Identity:        m.Identity,
		Website:         m.Website,
		SecurityContact: m.SecurityContact,
		Details:         m.Details,
	}

}

// ValsetQuery will create many queries for the valset contract
// See https://github.com/confio/tgrade-contracts/tree/v0.5.0-alpha/contracts/tgrade-valset/src/msg.rs
type ValsetQuery struct {
	Config                   *struct{}            `json:"config,omitempty"`
	Epoch                    *struct{}            `json:"epoch,omitempty"`
	Validator                *ValidatorQuery      `json:"validator,omitempty"`
	ListValidators           *ListValidatorsQuery `json:"list_validators,omitempty"`
	ListActiveValidators     *struct{}            `json:"list_active_validators,omitempty"`
	SimulateActiveValidators *struct{}            `json:"simulate_active_validators,omitempty"`
}

type ValidatorQuery struct {
	Operator string `json:"operator"`
}

type ListValidatorsQuery struct {
	StartAfter string `json:"start_after,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

// ValsetConfigResponse Response to `config` query
type ValsetConfigResponse struct {
	Membership    string   `json:"membership"`
	MinWeight     uint64   `json:"min_weight"`
	MaxValidators uint32   `json:"max_validators"`
	Scaling       uint32   `json:"scaling,omitempty"`
	EpochReward   sdk.Coin `json:"epoch_reward"`
	// Percentage of total accumulated fees which is substracted from tokens minted as a rewards. A fixed-point decimal value with 18 fractional digits, i.e. Decimal(1_000_000_000_000_000_000) == 1.0
	FeePercentage         sdk.Dec `json:"fee_percentage"`
	ValidatorsRewardRatio sdk.Dec `json:"validators_reward_ratio"`
	DistributionContract  string  `json:"distribution_contract,omitempty"`
	RewardsContract       string  `json:"rewards_contract"`
	AutoUnjail            bool    `json:"auto_unjail"`
}

// ValsetEpochQueryResponse Response to `config` query
type ValsetEpochResponse struct {
	// Number of seconds in one epoch. We update the Tendermint validator set only once per epoch.
	EpochLength uint64 `json:"epoch_length"`
	// The current epoch # (block.time/epoch_length, rounding down)
	CurrentEpoch uint64 `json:"current_epoch"`
	// The last time we updated the validator set - block time (in seconds)
	LastUpdateTime uint64 `json:"last_update_time"`
	// The last time we updated the validator set - block height
	LastUpdateHeight uint64 `json:"last_update_height"`
	// TODO: add this if you want it, not in current code
	/// Seconds (UTC UNIX time) of next timestamp that will trigger a validator recalculation
	//NextUpdateTime int `json:"next_update_time"`
}

type OperatorResponse struct {
	Operator string            `json:"operator"`
	Pubkey   ValidatorPubkey   `json:"pubkey"`
	Metadata ValidatorMetadata `json:"metadata"`
}

func (v OperatorResponse) ToValidator() (stakingtypes.Validator, error) {
	pubKey, err := toCosmosPubKey(v.Pubkey)
	if err != nil {
		return stakingtypes.Validator{}, sdkerrors.Wrap(err, "convert to cosmos key")
	}
	any, err := codectypes.NewAnyWithValue(pubKey)
	if err != nil {
		return stakingtypes.Validator{}, sdkerrors.Wrap(err, "convert to any type")
	}

	return stakingtypes.Validator{
		OperatorAddress: v.Operator,
		ConsensusPubkey: any,
		Description:     v.Metadata.ToDescription(),
		DelegatorShares: sdk.OneDec(),
		Status:          stakingtypes.Bonded,
	}, nil
}

func toCosmosPubKey(key ValidatorPubkey) (cryptotypes.PubKey, error) {
	switch {
	case key.Ed25519 != nil:
		return &ed25519.PubKey{Key: key.Ed25519}, nil
	case key.Secp256k1 != nil:
		return &cryptosecp256k1.PubKey{Key: key.Secp256k1}, nil
	default:
		return nil, types.ErrValidatorPubKeyTypeNotSupported
	}
}

type ValidatorInfo struct {
	Operator        string          `json:"operator"`
	ValidatorPubkey ValidatorPubkey `json:"validator_pubkey"`
	Power           uint64          `json:"power"`
}

type ValidatorResponse struct {
	Validator *OperatorResponse `json:"validator"`
}

type ListValidatorsResponse struct {
	Validators []OperatorResponse `json:"validators"`
}

type ListActiveValidatorsResponse struct {
	Validators []ValidatorInfo `json:"validators"`
}

type SimulateActiveValidatorsResponse = ListActiveValidatorsResponse

func QueryValsetConfig(ctx sdk.Context, k types.SmartQuerier, valset sdk.AccAddress) (*ValsetConfigResponse, error) {
	query := ValsetQuery{Config: &struct{}{}}
	var response ValsetConfigResponse
	err := doQuery(ctx, k, valset, query, &response)
	return &response, err
}

func QueryValsetEpoch(ctx sdk.Context, k types.SmartQuerier, valset sdk.AccAddress) (*ValsetEpochResponse, error) {
	query := ValsetQuery{Epoch: &struct{}{}}
	var response ValsetEpochResponse
	err := doQuery(ctx, k, valset, query, &response)
	return &response, err
}

func QueryValidator(ctx sdk.Context, k types.SmartQuerier, valset sdk.AccAddress, operator sdk.AccAddress) (*OperatorResponse, error) {
	query := ValsetQuery{Validator: &ValidatorQuery{Operator: operator.String()}}
	var response ValidatorResponse
	err := doQuery(ctx, k, valset, query, &response)
	return response.Validator, err
}

func ListValidators(ctx sdk.Context, k types.SmartQuerier, valset sdk.AccAddress) ([]OperatorResponse, error) {
	query := ValsetQuery{ListValidators: &ListValidatorsQuery{Limit: 30}}
	var response ListValidatorsResponse
	err := doQuery(ctx, k, valset, query, &response)
	return response.Validators, err
}

func ListActiveValidators(ctx sdk.Context, k types.SmartQuerier, valset sdk.AccAddress) ([]ValidatorInfo, error) {
	query := ValsetQuery{ListActiveValidators: &struct{}{}}
	var response ListActiveValidatorsResponse
	err := doQuery(ctx, k, valset, query, &response)
	return response.Validators, err
}

func SimulateActiveValidators(ctx sdk.Context, k types.SmartQuerier, valset sdk.AccAddress) ([]ValidatorInfo, error) {
	query := ValsetQuery{SimulateActiveValidators: &struct{}{}}
	var response ListActiveValidatorsResponse
	err := doQuery(ctx, k, valset, query, &response)
	return response.Validators, err
}
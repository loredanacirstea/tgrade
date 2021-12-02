package wasm

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk/types/query"

	wasmvmtypes "github.com/CosmWasm/wasmvm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/confio/tgrade/x/poe/types"

	"github.com/confio/tgrade/x/poe/keeper"
)

type ViewKeeper interface {
	GetBondDenom(ctx sdk.Context) string
	DistributionContract(ctx sdk.Context) keeper.DistributionContract
	ValsetContract(ctx sdk.Context) keeper.ValsetContract
	StakeContract(ctx sdk.Context) keeper.StakeContract
	GetPoEContractAddress(ctx sdk.Context, ctype types.PoEContractType) (sdk.AccAddress, error)
}

func StakingQuerier(poeKeeper ViewKeeper) func(ctx sdk.Context, request *wasmvmtypes.StakingQuery) ([]byte, error) {
	return func(ctx sdk.Context, request *wasmvmtypes.StakingQuery) ([]byte, error) {
		if request.BondedDenom != nil {
			denom := poeKeeper.GetBondDenom(ctx)
			res := wasmvmtypes.BondedDenomResponse{
				Denom: denom,
			}
			return json.Marshal(res)
		}
		zero := sdk.ZeroDec().String()
		if request.AllValidators != nil {
			var wasmVals []wasmvmtypes.Validator
			pagination := query.PageRequest{}
			for {
				validatorsBatch, err := poeKeeper.ValsetContract(ctx).ListValidators(ctx, &pagination)
				if err != nil {
					return nil, err
				}
				for _, v := range validatorsBatch {
					wasmVals = append(wasmVals, wasmvmtypes.Validator{
						Address:       v.OperatorAddress,
						Commission:    zero,
						MaxCommission: zero,
						MaxChangeRate: zero,
					},
					)
				}
				if len(validatorsBatch) == 0 {
					break
				}
				last := validatorsBatch[len(validatorsBatch)-1]
				pagination.Key = []byte(last.OperatorAddress)
			}
			res := wasmvmtypes.AllValidatorsResponse{
				Validators: wasmVals,
			}
			return json.Marshal(res)
		}
		if request.Validator != nil {
			valAddr, err := sdk.AccAddressFromBech32(request.Validator.Address)
			if err != nil {
				return nil, err
			}
			v, err := poeKeeper.ValsetContract(ctx).QueryValidator(ctx, valAddr)
			if err != nil {
				return nil, err
			}
			res := wasmvmtypes.ValidatorResponse{}
			if v != nil {
				res.Validator = &wasmvmtypes.Validator{
					Address:       v.OperatorAddress,
					Commission:    zero,
					MaxCommission: zero,
					MaxChangeRate: zero,
				}
			}
			return json.Marshal(res)
		}
		if request.AllDelegations != nil {
			delegator, err := sdk.AccAddressFromBech32(request.AllDelegations.Delegator)
			if err != nil {
				return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, request.AllDelegations.Delegator)
			}
			stakedAmount, err := poeKeeper.StakeContract(ctx).QueryStakedAmount(ctx, delegator)
			if err != nil {
				return nil, err
			}
			var res wasmvmtypes.AllDelegationsResponse
			if stakedAmount != nil {
				res.Delegations = []wasmvmtypes.Delegation{{
					Delegator: delegator.String(),
					Validator: delegator.String(),
					Amount:    wasmvmtypes.NewCoin(stakedAmount.Uint64(), poeKeeper.GetBondDenom(ctx)),
				}}
			}
			return json.Marshal(res)
		}
		if request.Delegation != nil {
			delegator, err := sdk.AccAddressFromBech32(request.Delegation.Delegator)
			if err != nil {
				return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, request.Delegation.Delegator)
			}
			validator, err := sdk.AccAddressFromBech32(request.Delegation.Validator)
			if err != nil {
				return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, request.Delegation.Validator)
			}

			var res wasmvmtypes.DelegationResponse
			if !delegator.Equals(validator) { // no match
				return json.Marshal(res)
			}
			stakeContract := poeKeeper.StakeContract(ctx)
			stakedAmount, err := stakeContract.QueryStakedAmount(ctx, delegator)
			if err != nil {
				return nil, sdkerrors.Wrap(err, "query staked amount")
			}
			reward, err := poeKeeper.DistributionContract(ctx).ValidatorOutstandingReward(ctx, delegator)
			if err != nil {
				return nil, sdkerrors.Wrap(err, "query outstanding reward")
			}
			if stakedAmount == nil {
				zeroInt := sdk.ZeroInt()
				stakedAmount = &zeroInt
			}
			// there can be unclaimed rewards while all stacked amounts were unbound
			if stakedAmount.GT(sdk.ZeroInt()) || reward.Amount.GT(sdk.ZeroInt()) {
				bondDenom := poeKeeper.GetBondDenom(ctx)
				stakedCoin := wasmvmtypes.NewCoin(stakedAmount.Uint64(), bondDenom)
				res.Delegation = &wasmvmtypes.FullDelegation{
					Delegator:          delegator.String(),
					Validator:          delegator.String(),
					Amount:             stakedCoin,
					CanRedelegate:      wasmvmtypes.NewCoin(0, bondDenom),
					AccumulatedRewards: wasmvmtypes.Coins{wasmvmtypes.NewCoin(reward.Amount.Uint64(), reward.Denom)},
				}
			}
			return json.Marshal(res)
		}
		return nil, wasmvmtypes.UnsupportedRequest{Kind: "unknown Staking variant"}
	}
}

type PoEContractAddressQuery struct {
	ContractType string `json:"contract_type"`
}

type TgradeQuery struct {
	PoEContractAddress *PoEContractAddressQuery `json:"poe_contract_address,omitempty"`
}

type ContractAddrResponse struct {
	Addr sdk.AccAddress `json:"address"`
}

func CustomQuerier(poeKeeper ViewKeeper) func(ctx sdk.Context, request json.RawMessage) ([]byte, error) {
	return func(ctx sdk.Context, request json.RawMessage) ([]byte, error) {
		var contractQuery TgradeQuery
		if err := json.Unmarshal(request, &contractQuery); err != nil {
			return nil, sdkerrors.Wrap(err, "tgrade query")
		}

		if contractQuery.PoEContractAddress != nil {
			ctype := types.PoEContractTypeFrom(contractQuery.PoEContractAddress.ContractType)

			addr, err := poeKeeper.GetPoEContractAddress(ctx, ctype)
			if err != nil {
				return nil, sdkerrors.Wrap(err, "poe contract address query")
			}

			res := ContractAddrResponse{
				Addr: addr,
			}
			bz, err := json.Marshal(res)
			if err != nil {
				return nil, sdkerrors.Wrap(err, "poe contract address query response")
			}
			return bz, nil
		}
		return nil, wasmvmtypes.UnsupportedRequest{Kind: "unknown poe query variant"}
	}
}
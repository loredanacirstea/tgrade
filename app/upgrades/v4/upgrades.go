package v4

import (
	"encoding/json"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/module"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"

	"github.com/confio/tgrade/x/poe/contract"
	poekeeper "github.com/confio/tgrade/x/poe/keeper"
	poetypes "github.com/confio/tgrade/x/poe/types"
)

const (
// oldEndTime int64 = 1703435178
// newEndTime int64 = 1688220000
)

var addresses = []string{
	"tgrade1s0lankh33kprer2l22nank5rvsuh9ksa4nr6gl",
}

func WhitelistedValidators() map[string]bool {
	result := make(map[string]bool)
	for _, item := range addresses {
		result[item] = true
	}
	return result
}

func CreateUpgradeHandler(
	mm *module.Manager,
	configurator module.Configurator,
	ak authkeeper.AccountKeeper,
	pk *poekeeper.Keeper,
	tk poetypes.TWasmKeeper,
) upgradetypes.UpgradeHandler {
	return func(ctx sdk.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
		// ibck

		// validators := pk.GetBondedValidatorsByPower(ctx)
		querier := poekeeper.NewQuerier(pk)
		fmt.Println("--CreateUpgradeHandler querier--", querier)
		// validators, err := querier.Validators(sdk.WrapSDKContext(ctx), &stakingtypes.QueryValidatorsRequest{})
		fmt.Println("--CreateUpgradeHandler ValsetContract--", pk.ValsetContract(ctx))
		validators, _, err := pk.ValsetContract(ctx).ListValidators(ctx, nil)
		fmt.Println("-validators-", err, validators)
		if err != nil {
			return nil, err
		}
		whitelist := WhitelistedValidators()
		stakingContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeStaking)
		if err != nil {
			return nil, err
		}
		fmt.Println("--stakingContractAddr--", stakingContractAddr)
		valsetContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeValset)
		if err != nil {
			return nil, err
		}
		fmt.Println("--valsetContractAddr--", valsetContractAddr)
		adminContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunityGovProposals)
		if err != nil {
			return nil, err
		}
		fmt.Println("--adminContractAddr--", adminContractAddr)
		oversightContractAddr, err := pk.GetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunity)
		if err != nil {
			return nil, err
		}
		fmt.Println("--oversightContractAddr--", oversightContractAddr)

		for _, val := range validators {
			if _, ok := whitelist[val.OperatorAddress]; ok {
				fmt.Println("----is in whitelist---", val.OperatorAddress)
				continue
			}
			fmt.Println("----BURN!---", val.OperatorAddress)
			opaddr, err := sdk.AccAddressFromBech32(val.OperatorAddress)
			if err != nil {
				return nil, fmt.Errorf("cannot convert bech32 to AccAddress: %s", val.OperatorAddress)
			}
			bondDenom := pk.GetBondDenom(ctx)
			// amount := sdk.Coin{Denom: poetypes.DefaultBondDenom, Amount: sdk.OneInt()}
			// sk.ValsetContract(ctx)

			amount, err := pk.StakeContract(ctx).QueryStakedAmount(ctx, opaddr)
			fmt.Println("--QueryStakedAmount--", err, amount)
			if err != nil {
				return nil, fmt.Errorf("cannot query staked amount: %s", val.OperatorAddress)
			}
			bondedAmount := sdk.Coin{Denom: bondDenom, Amount: *amount}
			fmt.Println("--bondedAmount--", bondedAmount)

			// msg := contract.TG4StakeExecute{Unbond: &contract.Unbond{Tokens: wasmvmtypes.NewCoin(amount.Uint64(), bondDenom)}}
			fmt.Println("--sdk.OneDec()--", sdk.OneDec())
			msg := contract.TG4ValsetExecute{Slash: &contract.Slash{Addr: val.OperatorAddress, Portion: sdk.OneDec()}}
			msgBz, err := json.Marshal(msg)
			if err != nil {
				return nil, sdkerrors.Wrap(err, "TG4StakeExecute message")
			}

			// ctx.WithEventManager(&em)
			if _, err = tk.GetContractKeeper().Execute(ctx, valsetContractAddr, adminContractAddr, msgBz, nil); err != nil {
				return nil, sdkerrors.Wrap(err, "execute staking contract")
			}

			amount, err = pk.StakeContract(ctx).QueryStakedAmount(ctx, opaddr)
			fmt.Println("--QueryStakedAmount END--", err, amount)

			// also jail
			jailDuration := contract.JailingDuration{Forever: &struct{}{}}
			jailMsg := contract.TG4ValsetExecute{Jail: &contract.JailMsg{Operator: val.OperatorAddress, Duration: jailDuration}}
			jailMsgBz, err := json.Marshal(jailMsg)
			if err != nil {
				return nil, sdkerrors.Wrap(err, "TG4StakeExecute message")
			}

			// ctx.WithEventManager(&em)
			if _, err = tk.GetContractKeeper().Execute(ctx, valsetContractAddr, adminContractAddr, jailMsgBz, nil); err != nil {
				return nil, sdkerrors.Wrap(err, "execute staking contract")
			}

			// unbondTime, err := contract.UnbondDelegation(ctx, stakingContractAddr, opaddr, bondedAmount, tk.GetContractKeeper())
			// fmt.Println("--unbondTime--", err, unbondTime)
			// if err != nil {
			// 	return nil, err
			// }
		}

		validators, _, err = pk.ValsetContract(ctx).ListValidators(ctx, nil)
		// fmt.Println("-validators2-", err, validators)
		for _, val := range validators {
			fmt.Println("-validator2 final-", val.Status.String(), val.Jailed, val.IsUnbonded(), val.IsUnbonding(), val.BondedTokens())
			opaddr, err := sdk.AccAddressFromBech32(val.OperatorAddress)
			if err != nil {
				return nil, fmt.Errorf("cannot convert bech32 to AccAddress: %s", val.OperatorAddress)
			}
			amount, err := pk.StakeContract(ctx).QueryStakedAmount(ctx, opaddr)
			fmt.Println("--QueryStakedAmount final--", val.OperatorAddress, err, amount)
			if err != nil {
				return nil, fmt.Errorf("cannot query staked amount: %s", val.OperatorAddress)
			}
		}

		newOcContractAddr := sdk.AccAddress{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		pk.SetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunity, newOcContractAddr)

		// // disable OC - set the trusted circle contract to a new contract without members
		// firstOCMember := sdk.AccAddress{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
		// ocInitMsg := newOCInitMsg(gs)
		// ocContractAddr, _, err := pk.Instantiate(
		// 	ctx,
		// 	trustedCircleCodeID,
		// 	firstOCMember,
		// 	bootstrapAccountAddr,
		// 	mustMarshalJSON(ocInitMsg),
		// 	"oversight_committee",
		// 	sdk.NewCoins(gs.OversightCommitteeContractConfig.EscrowAmount),
		// )
		// if err != nil {
		// 	return sdkerrors.Wrap(err, "instantiate tg trusted circle contract")
		// }
		// pk.SetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunity, ocContractAddr)

		// tcAdapter := contract.NewTrustedCircleContractAdapter(oversightContractAddr, tk, nil)
		// voters, err := tcAdapter.QueryListVoters(ctx)
		// fmt.Println("--QueryListVoters-", err, voters)

		// // admin, err := contract.QueryTG4Admin(ctx, tk, oversightContractAddr)
		// // fmt.Println("--QueryTG4Admin-", err, admin)

		// members, err := contract.QueryTG4Members(ctx, tk, oversightContractAddr, nil)
		// fmt.Println("--QueryTG4Members-", err, members)

		// memberAddresses := make([]string, len(members))
		// for i, mem := range members {
		// 	memberAddresses[i] = mem.Addr
		// }

		// // QueryTG4Admin
		// // QueryTG4Members

		// if len(memberAddresses) == 0 {
		// 	return nil, fmt.Errorf("no OC members")
		// }
		// fmt.Println("---memberAddresses--", memberAddresses)
		// memberaddr, err := sdk.AccAddressFromBech32(memberAddresses[0])
		// if err != nil {
		// 	return nil, fmt.Errorf("cannot convert bech32 to AccAddress: %s", memberAddresses[0])
		// }

		// err = tcAdapter.AddRemoveNonVotingMembers(ctx, memberAddresses, memberaddr)
		// if err != nil {
		// 	return nil, sdkerrors.Wrap(err, "remove voting members proposal")
		// }
		// latest, err := tcAdapter.LatestProposal(ctx)
		// if err != nil {
		// 	return nil, sdkerrors.Wrap(err, "query latest proposal")
		// }
		// err = tcAdapter.ExecuteProposal(ctx, latest.ID, memberaddr)
		// if err != nil {
		// 	return nil, sdkerrors.Wrap(err, "execute proposal")
		// }

		// members, err = contract.QueryTG4Members(ctx, tk, oversightContractAddr, nil)
		// fmt.Println("--QueryTG4Members END-", err, members)

		return mm.RunMigrations(ctx, configurator, fromVM)
	}
}

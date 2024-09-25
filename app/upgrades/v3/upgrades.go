package v3

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
	// we are scheduling the upgrade here
	// upgradeKeeper.ScheduleUpgrade(ctx, upgradePlan)

	fmt.Println("--CreateUpgradeHandler v3--")

	return func(ctx sdk.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
		// ibck

		// validators := pk.GetBondedValidatorsByPower(ctx)
		querier := poekeeper.NewQuerier(pk)
		fmt.Println("--CreateUpgradeHandler querier--", querier)
		// validators, err := querier.Validators(sdk.WrapSDKContext(ctx), &stakingtypes.QueryValidatorsRequest{})
		// fmt.Println("--CreateUpgradeHandler ValsetContract--", pk.ValsetContract(ctx))
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
			if err != nil || amount == nil {
				return nil, fmt.Errorf("cannot query staked amount: %s", val.OperatorAddress)
			}
			unbondduration, err := pk.StakeContract(ctx).QueryStakingUnbondingPeriod(ctx)
			fmt.Println("--unbondduration--", err, unbondduration)

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

		// disable oversight community contract
		newOcContractAddr := sdk.AccAddress{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		pk.SetPoEContractAddress(ctx, poetypes.PoEContractTypeOversightCommunity, newOcContractAddr)

		return mm.RunMigrations(ctx, configurator, fromVM)
	}
}

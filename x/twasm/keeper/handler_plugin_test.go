package keeper

import (
	"fmt"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"
	wasmvmtypes "github.com/CosmWasm/wasmvm/types"
	"github.com/confio/tgrade/x/twasm/contract"
	"github.com/confio/tgrade/x/twasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTgradeHandlesDispatchMsg(t *testing.T) {
	var (
		contractAddr = RandomAddress(t)
		otherAddr    = RandomAddress(t)
	)
	specs := map[string]struct {
		setup                 func(m *handlerTgradeKeeperMock)
		src                   wasmvmtypes.CosmosMsg
		expErr                *sdkerrors.Error
		expCapturedGovContent []govtypes.Content
	}{
		"handle privilege msg": {
			src: wasmvmtypes.CosmosMsg{
				Custom: []byte(`{"privilege":{"request":"begin_blocker"}}`),
			},
			setup: func(m *handlerTgradeKeeperMock) {
				noopRegisterHook(m)
			},
		},
		"handle execute gov proposal msg": {
			src: wasmvmtypes.CosmosMsg{
				Custom: []byte(`{"execute_gov_proposal":{"title":"foo", "description":"bar", "proposal":{"text":{}}}}`),
			},
			setup: func(m *handlerTgradeKeeperMock) {
				noopRegisterHook(m, func(info *wasmtypes.ContractInfo) {
					var details types.TgradeContractDetails
					require.NoError(t, info.ReadExtension(&details))
					details.AddRegisteredPrivilege(types.PrivilegeTypeGovProposalExecutor, 1)
					require.NoError(t, info.SetExtension(&details))
				})
			},
			expCapturedGovContent: []govtypes.Content{&govtypes.TextProposal{Title: "foo", Description: "bar"}},
		},
		"handle minter msg": {
			src: wasmvmtypes.CosmosMsg{
				Custom: []byte(fmt.Sprintf(`{"mint_tokens":{"amount":"1","denom":"utgd","recipient":%q}}`, otherAddr.String())),
			},
			setup: func(m *handlerTgradeKeeperMock) {
				noopRegisterHook(m, func(info *wasmtypes.ContractInfo) {
					var details types.TgradeContractDetails
					require.NoError(t, info.ReadExtension(&details))
					details.AddRegisteredPrivilege(types.PrivilegeTypeTokenMinter, 1)
					require.NoError(t, info.SetExtension(&details))
				})
			},
		},
		"non custom msg rejected": {
			src:    wasmvmtypes.CosmosMsg{},
			setup:  func(m *handlerTgradeKeeperMock) {},
			expErr: wasmtypes.ErrUnknownMsg,
		},
		"non privileged contracts rejected": {
			src: wasmvmtypes.CosmosMsg{Custom: []byte(`{}`)},
			setup: func(m *handlerTgradeKeeperMock) {
				m.IsPrivilegedFn = func(ctx sdk.Context, contract sdk.AccAddress) bool {
					return false
				}
			},
			expErr: wasmtypes.ErrUnknownMsg,
		},
		"invalid json rejected": {
			src: wasmvmtypes.CosmosMsg{Custom: []byte(`not json`)},
			setup: func(m *handlerTgradeKeeperMock) {
				m.IsPrivilegedFn = func(ctx sdk.Context, contract sdk.AccAddress) bool {
					return true
				}
			},
			expErr: sdkerrors.ErrJSONUnmarshal,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			cdc := MakeEncodingConfig(t).Marshaler
			govRouter := &CapturingGovRouter{}
			minterMock := NoopMinterMock()
			mock := handlerTgradeKeeperMock{}
			spec.setup(&mock)
			h := NewTgradeHandler(cdc, mock, minterMock, govRouter)
			var ctx sdk.Context
			_, _, gotErr := h.DispatchMsg(ctx, contractAddr, "", spec.src)
			require.True(t, spec.expErr.Is(gotErr), "expected %v but got %#+v", spec.expErr, gotErr)
			assert.Equal(t, spec.expCapturedGovContent, govRouter.captured)
		})
	}
}

type registration struct {
	cb   types.PrivilegeType
	addr sdk.AccAddress
}
type unregistration struct {
	cb   types.PrivilegeType
	pos  uint8
	addr sdk.AccAddress
}

func TestTgradeHandlesPrivilegeMsg(t *testing.T) {
	myContractAddr := RandomAddress(t)

	var capturedDetails *types.TgradeContractDetails
	captureContractDetails := func(ctx sdk.Context, contract sdk.AccAddress, details *types.TgradeContractDetails) error {
		require.Equal(t, myContractAddr, contract)
		capturedDetails = details
		return nil
	}

	var capturedRegistrations []registration
	captureRegistrations := func(ctx sdk.Context, privilegeType types.PrivilegeType, contractAddress sdk.AccAddress) (uint8, error) {
		capturedRegistrations = append(capturedRegistrations, registration{cb: privilegeType, addr: contractAddress})
		return 1, nil
	}
	var capturedUnRegistrations []unregistration
	captureUnRegistrations := func(ctx sdk.Context, privilegeType types.PrivilegeType, pos uint8, contractAddress sdk.AccAddress) bool {
		capturedUnRegistrations = append(capturedUnRegistrations, unregistration{cb: privilegeType, pos: pos, addr: contractAddress})
		return true
	}

	captureWithMock := func(mutators ...func(*wasmtypes.ContractInfo)) func(mock *handlerTgradeKeeperMock) {
		return func(m *handlerTgradeKeeperMock) {
			m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
				f := wasmtypes.ContractInfoFixture(mutators...)
				return &f
			}
			m.setContractDetailsFn = captureContractDetails
			m.appendToPrivilegedContractsFn = captureRegistrations
			m.removePrivilegeRegistrationFn = captureUnRegistrations
		}
	}

	specs := map[string]struct {
		setup              func(m *handlerTgradeKeeperMock)
		src                contract.PrivilegeMsg
		expDetails         *types.TgradeContractDetails
		expRegistrations   []registration
		expUnRegistrations []unregistration
		expErr             *sdkerrors.Error
	}{
		"register begin block": {
			src:   contract.PrivilegeMsg{Request: types.PrivilegeTypeBeginBlock},
			setup: captureWithMock(),
			expDetails: &types.TgradeContractDetails{
				RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "begin_blocker"}},
			},
			expRegistrations: []registration{{cb: types.PrivilegeTypeBeginBlock, addr: myContractAddr}},
		},
		"unregister begin block": {
			src: contract.PrivilegeMsg{Release: types.PrivilegeTypeBeginBlock},
			setup: captureWithMock(func(info *wasmtypes.ContractInfo) {
				ext := &types.TgradeContractDetails{
					RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "begin_blocker"}},
				}
				info.SetExtension(ext)
			}),
			expDetails:         &types.TgradeContractDetails{RegisteredPrivileges: []types.RegisteredPrivilege{}},
			expUnRegistrations: []unregistration{{cb: types.PrivilegeTypeBeginBlock, pos: 1, addr: myContractAddr}},
		},
		"register end block": {
			src:   contract.PrivilegeMsg{Request: types.PrivilegeTypeEndBlock},
			setup: captureWithMock(),
			expDetails: &types.TgradeContractDetails{
				RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "end_blocker"}},
			},
			expRegistrations: []registration{{cb: types.PrivilegeTypeEndBlock, addr: myContractAddr}},
		},
		"unregister end block": {
			src: contract.PrivilegeMsg{Release: types.PrivilegeTypeEndBlock},
			setup: captureWithMock(func(info *wasmtypes.ContractInfo) {
				ext := &types.TgradeContractDetails{
					RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "end_blocker"}},
				}
				info.SetExtension(ext)
			}),
			expDetails:         &types.TgradeContractDetails{RegisteredPrivileges: []types.RegisteredPrivilege{}},
			expUnRegistrations: []unregistration{{cb: types.PrivilegeTypeEndBlock, pos: 1, addr: myContractAddr}},
		},
		"register validator set update block": {
			src:   contract.PrivilegeMsg{Request: types.PrivilegeTypeValidatorSetUpdate},
			setup: captureWithMock(),
			expDetails: &types.TgradeContractDetails{
				RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "validator_set_updater"}},
			},
			expRegistrations: []registration{{cb: types.PrivilegeTypeValidatorSetUpdate, addr: myContractAddr}},
		},
		"unregister validator set update block": {
			src: contract.PrivilegeMsg{Release: types.PrivilegeTypeValidatorSetUpdate},
			setup: captureWithMock(func(info *wasmtypes.ContractInfo) {
				ext := &types.TgradeContractDetails{
					RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "validator_set_updater"}},
				}
				info.SetExtension(ext)
			}),
			expDetails:         &types.TgradeContractDetails{RegisteredPrivileges: []types.RegisteredPrivilege{}},
			expUnRegistrations: []unregistration{{cb: types.PrivilegeTypeValidatorSetUpdate, pos: 1, addr: myContractAddr}},
		},
		"register gov proposal executor": {
			src:   contract.PrivilegeMsg{Request: types.PrivilegeTypeGovProposalExecutor},
			setup: captureWithMock(),
			expDetails: &types.TgradeContractDetails{
				RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "gov_proposal_executor"}},
			},
			expRegistrations: []registration{{cb: types.PrivilegeTypeGovProposalExecutor, addr: myContractAddr}},
		},
		"unregister gov proposal executor": {
			src: contract.PrivilegeMsg{Release: types.PrivilegeTypeGovProposalExecutor},
			setup: captureWithMock(func(info *wasmtypes.ContractInfo) {
				ext := &types.TgradeContractDetails{
					RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "gov_proposal_executor"}},
				}
				info.SetExtension(ext)
			}),
			expDetails:         &types.TgradeContractDetails{RegisteredPrivileges: []types.RegisteredPrivilege{}},
			expUnRegistrations: []unregistration{{cb: types.PrivilegeTypeGovProposalExecutor, pos: 1, addr: myContractAddr}},
		},
		"register privilege fails": {
			src: contract.PrivilegeMsg{Request: types.PrivilegeTypeValidatorSetUpdate},
			setup: func(m *handlerTgradeKeeperMock) {
				m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					r := wasmtypes.ContractInfoFixture()
					return &r
				}
				m.appendToPrivilegedContractsFn = func(ctx sdk.Context, privilegeType types.PrivilegeType, contractAddress sdk.AccAddress) (uint8, error) {
					return 0, wasmtypes.ErrDuplicate
				}
			},
			expErr: wasmtypes.ErrDuplicate,
		},
		"register begin block with existing registration": {
			src: contract.PrivilegeMsg{Request: types.PrivilegeTypeBeginBlock},
			setup: captureWithMock(func(info *wasmtypes.ContractInfo) {
				info.SetExtension(&types.TgradeContractDetails{
					RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "begin_blocker"}},
				})
			}),
		},
		"register appends to existing callback list": {
			src: contract.PrivilegeMsg{Request: types.PrivilegeTypeBeginBlock},
			setup: captureWithMock(func(info *wasmtypes.ContractInfo) {
				info.SetExtension(&types.TgradeContractDetails{
					RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 100, PrivilegeType: "end_blocker"}},
				})
			}),
			expDetails: &types.TgradeContractDetails{
				RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 100, PrivilegeType: "end_blocker"}, {Position: 1, PrivilegeType: "begin_blocker"}},
			},
			expRegistrations: []registration{{cb: types.PrivilegeTypeBeginBlock, addr: myContractAddr}},
		},
		"unregister removed from existing callback list": {
			src: contract.PrivilegeMsg{Release: types.PrivilegeTypeBeginBlock},
			setup: captureWithMock(func(info *wasmtypes.ContractInfo) {
				ext := &types.TgradeContractDetails{
					RegisteredPrivileges: []types.RegisteredPrivilege{
						{Position: 3, PrivilegeType: "validator_set_updater"},
						{Position: 1, PrivilegeType: "begin_blocker"},
						{Position: 100, PrivilegeType: "end_blocker"},
					},
				}
				info.SetExtension(ext)
			}),
			expDetails: &types.TgradeContractDetails{RegisteredPrivileges: []types.RegisteredPrivilege{
				{Position: 3, PrivilegeType: "validator_set_updater"},
				{Position: 100, PrivilegeType: "end_blocker"},
			}},
			expUnRegistrations: []unregistration{{cb: types.PrivilegeTypeBeginBlock, pos: 1, addr: myContractAddr}},
		},

		"unregister begin block with without existing registration": {
			src:   contract.PrivilegeMsg{Release: types.PrivilegeTypeBeginBlock},
			setup: captureWithMock(),
		},
		"empty privilege msg rejected": {
			setup: func(m *handlerTgradeKeeperMock) {
				noopRegisterHook(m)
			},
			expErr: wasmtypes.ErrUnknownMsg,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			capturedDetails, capturedRegistrations, capturedUnRegistrations = nil, nil, nil
			mock := handlerTgradeKeeperMock{}
			spec.setup(&mock)
			h := NewTgradeHandler(nil, mock, nil, nil)
			var ctx sdk.Context
			gotErr := h.handlePrivilege(ctx, myContractAddr, &spec.src)
			require.True(t, spec.expErr.Is(gotErr), "expected %v but got %#+v", spec.expErr, gotErr)
			if spec.expErr != nil {
				return
			}
			assert.Equal(t, spec.expDetails, capturedDetails)
			assert.Equal(t, spec.expRegistrations, capturedRegistrations)
			assert.Equal(t, spec.expUnRegistrations, capturedUnRegistrations)
		})
	}
}

func TestHandleGovProposalExecution(t *testing.T) {
	myContractAddr := RandomAddress(t)
	specs := map[string]struct {
		src                   contract.ExecuteGovProposal
		setup                 func(m *handlerTgradeKeeperMock)
		expErr                *sdkerrors.Error
		expCapturedGovContent []govtypes.Content
	}{
		"all good": {
			src: contract.ExecuteGovProposalFixture(),
			setup: func(m *handlerTgradeKeeperMock) {
				m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "gov_proposal_executor"}},
						})
					})
					return &c
				}
			},
			expCapturedGovContent: []govtypes.Content{&govtypes.TextProposal{Title: "foo", Description: "bar"}},
		},
		"unauthorized contract": {
			src: contract.ExecuteGovProposalFixture(),
			setup: func(m *handlerTgradeKeeperMock) {
				m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture()
					return &c
				}
			},
			expErr: sdkerrors.ErrUnauthorized,
		},
		"invalid content": {
			src: contract.ExecuteGovProposalFixture(func(p *contract.ExecuteGovProposal) {
				p.Proposal = contract.GovProposalFixture(func(x *contract.GovProposal) {
					x.RegisterUpgrade = &upgradetypes.Plan{}
				})
			}),
			setup: func(m *handlerTgradeKeeperMock) {
				m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "gov_proposal_executor"}},
						})
					})
					return &c
				}
			},
			expErr: sdkerrors.ErrInvalidRequest,
		},
		"no content": {
			src: contract.ExecuteGovProposal{Title: "foo", Description: "bar"},
			setup: func(m *handlerTgradeKeeperMock) {
				m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "gov_proposal_executor"}},
						})
					})
					return &c
				}
			},
			expErr: wasmtypes.ErrUnknownMsg,
		},
		"unknown origin contract": {
			src: contract.ExecuteGovProposalFixture(),
			setup: func(m *handlerTgradeKeeperMock) {
				m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					return nil
				}
			},
			expErr: wasmtypes.ErrNotFound,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			cdc := MakeEncodingConfig(t).Marshaler
			mock := handlerTgradeKeeperMock{}
			spec.setup(&mock)
			router := &CapturingGovRouter{}
			h := NewTgradeHandler(cdc, mock, nil, router)
			var ctx sdk.Context
			gotErr := h.handleGovProposalExecution(ctx, myContractAddr, &spec.src)
			require.True(t, spec.expErr.Is(gotErr), "expected %v but got %#+v", spec.expErr, gotErr)
			assert.Equal(t, spec.expCapturedGovContent, router.captured)
		})
	}

}

func TestHandleMintToken(t *testing.T) {
	myContractAddr := RandomAddress(t)
	myRecipientAddr := RandomAddress(t)
	specs := map[string]struct {
		src            contract.MintTokens
		setup          func(k *handlerTgradeKeeperMock)
		expErr         *sdkerrors.Error
		expMintedCoins sdk.Coins
		expRecipient   sdk.AccAddress
	}{
		"all good": {
			src: contract.MintTokens{
				Denom:         "foo",
				Amount:        "123",
				RecipientAddr: myRecipientAddr.String(),
			},
			setup: func(k *handlerTgradeKeeperMock) {
				k.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "token_minter"}},
						})
					})
					return &c
				}
			},
			expMintedCoins: sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(123))),
			expRecipient:   myRecipientAddr,
		},
		"unauthorized contract": {
			src: contract.MintTokens{
				Denom:         "foo",
				Amount:        "123",
				RecipientAddr: myRecipientAddr.String(),
			},
			setup: func(k *handlerTgradeKeeperMock) {
				k.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{},
						})
					})
					return &c
				}
			},
			expErr: sdkerrors.ErrUnauthorized,
		},
		"invalid denom": {
			src: contract.MintTokens{
				Denom:         "&&&foo",
				Amount:        "123",
				RecipientAddr: myRecipientAddr.String(),
			},
			setup: func(k *handlerTgradeKeeperMock) {
				k.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "token_minter"}},
						})
					})
					return &c
				}
			},
			expErr: sdkerrors.ErrInvalidCoins,
		},
		"invalid amount": {
			src: contract.MintTokens{
				Denom:         "foo",
				Amount:        "not-a-number",
				RecipientAddr: myRecipientAddr.String(),
			},
			setup: func(k *handlerTgradeKeeperMock) {
				k.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "token_minter"}},
						})
					})
					return &c
				}
			},
			expErr: sdkerrors.ErrInvalidCoins,
		},
		"invalid recipient": {
			src: contract.MintTokens{
				Denom:         "foo",
				Amount:        "123",
				RecipientAddr: "not-an-address",
			},
			setup: func(k *handlerTgradeKeeperMock) {
				k.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "token_minter"}},
						})
					})
					return &c
				}
			},
			expErr: sdkerrors.ErrInvalidAddress,
		},
		"no content": {
			src: contract.MintTokens{},
			setup: func(k *handlerTgradeKeeperMock) {
				k.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					c := wasmtypes.ContractInfoFixture(func(info *wasmtypes.ContractInfo) {
						info.SetExtension(&types.TgradeContractDetails{
							RegisteredPrivileges: []types.RegisteredPrivilege{{Position: 1, PrivilegeType: "token_minter"}},
						})
					})
					return &c
				}
			},
			expErr: sdkerrors.ErrInvalidAddress,
		},
		"unknown origin contract": {
			src: contract.MintTokens{
				Denom:         "foo",
				Amount:        "123",
				RecipientAddr: "not-an-address",
			},
			setup: func(m *handlerTgradeKeeperMock) {
				m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
					return nil
				}
			},
			expErr: wasmtypes.ErrNotFound,
		},
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			cdc := MakeEncodingConfig(t).Marshaler
			mintFn, capturedMintedCoins := CaptureMintedCoinsFn()
			sendFn, capturedSentCoins := CaptureSendCoinsFn()
			mock := MinterMock{MintCoinsFn: mintFn, SendCoinsFromModuleToAccountFn: sendFn}
			keeperMock := handlerTgradeKeeperMock{}
			spec.setup(&keeperMock)
			h := NewTgradeHandler(cdc, keeperMock, mock, nil)
			var ctx sdk.Context
			gotEvts, gotErr := h.handleMintToken(ctx, myContractAddr, &spec.src)
			require.True(t, spec.expErr.Is(gotErr), "expected %v but got %#+v", spec.expErr, gotErr)
			if spec.expErr != nil {
				assert.Len(t, gotEvts, 0)
				return
			}
			require.Len(t, *capturedMintedCoins, 1)
			assert.Equal(t, spec.expMintedCoins, (*capturedMintedCoins)[0])
			require.Len(t, *capturedSentCoins, 1)
			assert.Equal(t, (*capturedSentCoins)[0].coins, spec.expMintedCoins)
			assert.Equal(t, (*capturedSentCoins)[0].recipientAddr, spec.expRecipient)
			require.Len(t, gotEvts, 1)
			assert.Equal(t, types.EventTypeRewards, gotEvts[0].Type)
		})
	}
}

// noopRegisterHook does nothing and but all methods for registration
func noopRegisterHook(m *handlerTgradeKeeperMock, mutators ...func(*wasmtypes.ContractInfo)) {
	m.IsPrivilegedFn = func(ctx sdk.Context, contract sdk.AccAddress) bool {
		return true
	}
	m.GetContractInfoFn = func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
		v := wasmtypes.ContractInfoFixture(append([]func(*wasmtypes.ContractInfo){func(info *wasmtypes.ContractInfo) {
			info.SetExtension(&types.TgradeContractDetails{})
		}}, mutators...)...)
		return &v
	}
	m.appendToPrivilegedContractsFn = func(ctx sdk.Context, privilegeType types.PrivilegeType, contractAddress sdk.AccAddress) (uint8, error) {
		return 1, nil
	}
	m.setContractDetailsFn = func(ctx sdk.Context, contract sdk.AccAddress, details *types.TgradeContractDetails) error {
		return nil
	}
}

var _ tgradeKeeper = handlerTgradeKeeperMock{}

type handlerTgradeKeeperMock struct {
	IsPrivilegedFn                func(ctx sdk.Context, contract sdk.AccAddress) bool
	appendToPrivilegedContractsFn func(ctx sdk.Context, privilegeType types.PrivilegeType, contractAddress sdk.AccAddress) (uint8, error)
	removePrivilegeRegistrationFn func(ctx sdk.Context, privilegeType types.PrivilegeType, pos uint8, contractAddr sdk.AccAddress) bool
	setContractDetailsFn          func(ctx sdk.Context, contract sdk.AccAddress, details *types.TgradeContractDetails) error
	GetContractInfoFn             func(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo
}

func (m handlerTgradeKeeperMock) IsPrivileged(ctx sdk.Context, contract sdk.AccAddress) bool {
	if m.IsPrivilegedFn == nil {
		panic("not expected to be called")
	}
	return m.IsPrivilegedFn(ctx, contract)
}

func (m handlerTgradeKeeperMock) appendToPrivilegedContracts(ctx sdk.Context, privilegeType types.PrivilegeType, contractAddress sdk.AccAddress) (uint8, error) {
	if m.appendToPrivilegedContractsFn == nil {
		panic("not expected to be called")
	}
	return m.appendToPrivilegedContractsFn(ctx, privilegeType, contractAddress)
}

func (m handlerTgradeKeeperMock) removePrivilegeRegistration(ctx sdk.Context, privilegeType types.PrivilegeType, pos uint8, contractAddr sdk.AccAddress) bool {
	if m.removePrivilegeRegistrationFn == nil {
		panic("not expected to be called")
	}
	return m.removePrivilegeRegistrationFn(ctx, privilegeType, pos, contractAddr)
}

func (m handlerTgradeKeeperMock) setContractDetails(ctx sdk.Context, contract sdk.AccAddress, details *types.TgradeContractDetails) error {
	if m.setContractDetailsFn == nil {
		panic("not expected to be called")
	}
	return m.setContractDetailsFn(ctx, contract, details)
}

func (m handlerTgradeKeeperMock) GetContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress) *wasmtypes.ContractInfo {
	if m.GetContractInfoFn == nil {
		panic("not expected to be called")
	}
	return m.GetContractInfoFn(ctx, contractAddress)
}

// MinterMock test helper that satisfies the `minter` interface
type MinterMock struct {
	MintCoinsFn                    func(ctx sdk.Context, moduleName string, amt sdk.Coins) error
	SendCoinsFromModuleToAccountFn func(ctx sdk.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
}

func (m MinterMock) MintCoins(ctx sdk.Context, moduleName string, amt sdk.Coins) error {
	if m.MintCoinsFn == nil {
		panic("not expected to be called")
	}
	return m.MintCoinsFn(ctx, moduleName, amt)
}

func (m MinterMock) SendCoinsFromModuleToAccount(ctx sdk.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error {
	if m.SendCoinsFromModuleToAccountFn == nil {
		panic("not expected to be called")
	}
	return m.SendCoinsFromModuleToAccountFn(ctx, senderModule, recipientAddr, amt)
}

func NoopMinterMock() *MinterMock {
	return &MinterMock{
		MintCoinsFn: func(ctx sdk.Context, moduleName string, amt sdk.Coins) error {
			return nil
		},
		SendCoinsFromModuleToAccountFn: func(ctx sdk.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error {
			return nil
		},
	}
}

func CaptureMintedCoinsFn() (func(ctx sdk.Context, moduleName string, amt sdk.Coins) error, *[]sdk.Coins) {
	var r []sdk.Coins
	return func(ctx sdk.Context, moduleName string, amt sdk.Coins) error {
		r = append(r, amt)
		return nil
	}, &r
}

type capturedSendCoins struct {
	recipientAddr sdk.AccAddress
	coins         sdk.Coins
}

func CaptureSendCoinsFn() (func(ctx sdk.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error, *[]capturedSendCoins) {
	var r []capturedSendCoins
	return func(ctx sdk.Context, moduleName string, recipientAddr sdk.AccAddress, amt sdk.Coins) error {
		r = append(r, capturedSendCoins{recipientAddr: recipientAddr, coins: amt})
		return nil
	}, &r
}
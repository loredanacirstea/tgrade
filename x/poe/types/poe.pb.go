// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: confio/poe/v1beta1/poe.proto

package types

import (
	fmt "fmt"
	_ "github.com/cosmos/cosmos-proto"
	_ "github.com/cosmos/cosmos-sdk/codec/types"
	github_com_cosmos_cosmos_sdk_types "github.com/cosmos/cosmos-sdk/types"
	types "github.com/cosmos/cosmos-sdk/types"
	_ "github.com/cosmos/cosmos-sdk/x/staking/types"
	_ "github.com/cosmos/gogoproto/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/tendermint/tendermint/proto/tendermint/types"
	_ "google.golang.org/protobuf/types/known/durationpb"
	_ "google.golang.org/protobuf/types/known/timestamppb"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// PoEContractType type of PoE contract
type PoEContractType int32

const (
	PoEContractTypeUndefined                      PoEContractType = 0
	PoEContractTypeStaking                        PoEContractType = 1
	PoEContractTypeValset                         PoEContractType = 2
	PoEContractTypeEngagement                     PoEContractType = 3
	PoEContractTypeMixer                          PoEContractType = 4
	PoEContractTypeDistribution                   PoEContractType = 5
	PoEContractTypeOversightCommunity             PoEContractType = 6
	PoEContractTypeOversightCommunityGovProposals PoEContractType = 7
	PoEContractTypeCommunityPool                  PoEContractType = 8
	PoEContractTypeValidatorVoting                PoEContractType = 9
	PoEContractTypeArbiterPool                    PoEContractType = 10
	PoEContractTypeArbiterPoolVoting              PoEContractType = 11
)

var PoEContractType_name = map[int32]string{
	0:  "UNDEFINED",
	1:  "STAKING",
	2:  "VALSET",
	3:  "ENGAGEMENT",
	4:  "MIXER",
	5:  "DISTRIBUTION",
	6:  "OVERSIGHT_COMMUNITY",
	7:  "OVERSIGHT_COMMUNITY_PROPOSALS",
	8:  "COMMUNITY_POOL",
	9:  "VALIDATOR_VOTING",
	10: "ARBITER_POOL",
	11: "ARBITER_POOL_VOTING",
}

var PoEContractType_value = map[string]int32{
	"UNDEFINED":                     0,
	"STAKING":                       1,
	"VALSET":                        2,
	"ENGAGEMENT":                    3,
	"MIXER":                         4,
	"DISTRIBUTION":                  5,
	"OVERSIGHT_COMMUNITY":           6,
	"OVERSIGHT_COMMUNITY_PROPOSALS": 7,
	"COMMUNITY_POOL":                8,
	"VALIDATOR_VOTING":              9,
	"ARBITER_POOL":                  10,
	"ARBITER_POOL_VOTING":           11,
}

func (x PoEContractType) String() string {
	return proto.EnumName(PoEContractType_name, int32(x))
}

func (PoEContractType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_df6d9ea68813554a, []int{0}
}

// Params defines the parameters for the PoE module.
type Params struct {
	// HistoricalEntries is the number of historical entries to persist.
	HistoricalEntries uint32 `protobuf:"varint,1,opt,name=historical_entries,json=historicalEntries,proto3" json:"historical_entries,omitempty" yaml:"historical_entries"`
	// InitialValEngagementPoints defines the number of engagement for any new
	// validator joining post genesis
	InitialValEngagementPoints uint64 `protobuf:"varint,2,opt,name=initial_val_engagement_points,json=initialValEngagementPoints,proto3" json:"initial_val_engagement_points,omitempty" yaml:"initial_val_engagement_points"`
	// MinDelegationAmount defines the minimum amount a post genesis validator
	// needs to self delegate to receive any engagement points. One must be
	// exceeded. No minimum condition set when empty.
	MinDelegationAmounts github_com_cosmos_cosmos_sdk_types.Coins `protobuf:"bytes,3,rep,name=min_delegation_amounts,json=minDelegationAmounts,proto3,castrepeated=github.com/cosmos/cosmos-sdk/types.Coins" json:"min_delegation_amounts" yaml:"min_delegation_amounts"`
}

func (m *Params) Reset()      { *m = Params{} }
func (*Params) ProtoMessage() {}
func (*Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_df6d9ea68813554a, []int{0}
}
func (m *Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params.Merge(m, src)
}
func (m *Params) XXX_Size() int {
	return m.Size()
}
func (m *Params) XXX_DiscardUnknown() {
	xxx_messageInfo_Params.DiscardUnknown(m)
}

var xxx_messageInfo_Params proto.InternalMessageInfo

func (m *Params) GetHistoricalEntries() uint32 {
	if m != nil {
		return m.HistoricalEntries
	}
	return 0
}

func (m *Params) GetInitialValEngagementPoints() uint64 {
	if m != nil {
		return m.InitialValEngagementPoints
	}
	return 0
}

func (m *Params) GetMinDelegationAmounts() github_com_cosmos_cosmos_sdk_types.Coins {
	if m != nil {
		return m.MinDelegationAmounts
	}
	return nil
}

func init() {
	proto.RegisterEnum("confio.poe.v1beta1.PoEContractType", PoEContractType_name, PoEContractType_value)
	proto.RegisterType((*Params)(nil), "confio.poe.v1beta1.Params")
}

func init() { proto.RegisterFile("confio/poe/v1beta1/poe.proto", fileDescriptor_df6d9ea68813554a) }

var fileDescriptor_df6d9ea68813554a = []byte{
	// 806 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x54, 0x4f, 0x6f, 0xe3, 0x44,
	0x1c, 0x4d, 0xfa, 0x6f, 0x77, 0x67, 0x17, 0x30, 0xde, 0xb2, 0x6a, 0x86, 0xc6, 0x1e, 0x42, 0x57,
	0x44, 0xa0, 0x26, 0x14, 0x38, 0xa0, 0x95, 0x58, 0xc9, 0x69, 0x4c, 0xb0, 0x48, 0xe2, 0xe0, 0xb8,
	0x11, 0x70, 0xb1, 0x26, 0xc9, 0xd4, 0x1d, 0x35, 0x9e, 0x89, 0x3c, 0x93, 0x6a, 0xf3, 0x0d, 0x90,
	0x4f, 0x88, 0x13, 0x17, 0x4b, 0x2b, 0xb8, 0xf1, 0x49, 0xf6, 0xb8, 0x47, 0x4e, 0x05, 0xb5, 0x17,
	0xce, 0xfd, 0x04, 0xc8, 0x7f, 0xd2, 0x2e, 0xde, 0x02, 0x17, 0x7b, 0x7e, 0xf3, 0xde, 0xef, 0xbd,
	0xd1, 0xfb, 0x8d, 0x06, 0xec, 0x4e, 0x38, 0x3b, 0xa6, 0xbc, 0x39, 0xe7, 0xa4, 0x79, 0x76, 0x30,
	0x26, 0x12, 0x1f, 0x24, 0xeb, 0xc6, 0x3c, 0xe4, 0x92, 0xab, 0x6a, 0x86, 0x36, 0x92, 0x9d, 0x1c,
	0x85, 0xdb, 0x3e, 0xf7, 0x79, 0x0a, 0x37, 0x93, 0x55, 0xc6, 0x84, 0x15, 0x9f, 0x73, 0x7f, 0x46,
	0x9a, 0x69, 0x35, 0x5e, 0x1c, 0x37, 0x31, 0x5b, 0xe6, 0x90, 0x56, 0x84, 0xa6, 0x8b, 0x10, 0x4b,
	0xca, 0x59, 0x8e, 0xeb, 0x45, 0x5c, 0xd2, 0x80, 0x08, 0x89, 0x83, 0xf9, 0x4a, 0x7b, 0xc2, 0x45,
	0xc0, 0x85, 0x97, 0x99, 0x66, 0xc5, 0x4a, 0x3b, 0xab, 0x9a, 0x63, 0x2c, 0x6e, 0xce, 0x3f, 0xe1,
	0x74, 0xa5, 0xbd, 0x97, 0xe3, 0x42, 0xe2, 0x53, 0xca, 0xfc, 0x6b, 0x4a, 0x5e, 0xe7, 0xac, 0x5d,
	0x49, 0xd8, 0x94, 0x84, 0x01, 0x65, 0xb2, 0x29, 0x97, 0x73, 0x22, 0xb2, 0x6f, 0x86, 0xd6, 0xae,
	0xd6, 0xc0, 0xd6, 0x00, 0x87, 0x38, 0x10, 0x6a, 0x17, 0xa8, 0x27, 0x54, 0x48, 0x1e, 0xd2, 0x09,
	0x9e, 0x79, 0x84, 0xc9, 0x90, 0x12, 0xb1, 0x53, 0x46, 0xe5, 0xfa, 0x1b, 0xad, 0xea, 0xd5, 0xb9,
	0x5e, 0x59, 0xe2, 0x60, 0xf6, 0xa4, 0xf6, 0x3a, 0xa7, 0xe6, 0xbc, 0x7d, 0xb3, 0x69, 0x66, 0x7b,
	0xea, 0x29, 0xa8, 0x52, 0x46, 0x25, 0xc5, 0x33, 0xef, 0x2c, 0xa5, 0xfa, 0xd8, 0x27, 0x01, 0x61,
	0xd2, 0x9b, 0x73, 0xca, 0xa4, 0xd8, 0x59, 0x43, 0xe5, 0xfa, 0x46, 0xab, 0x7e, 0x75, 0xae, 0xef,
	0x65, 0xc2, 0xff, 0x49, 0xaf, 0x39, 0x30, 0xc7, 0x47, 0x89, 0xc7, 0x0a, 0x1d, 0xa4, 0xa0, 0xfa,
	0x4b, 0x19, 0x3c, 0x0a, 0x28, 0xf3, 0xa6, 0x64, 0x46, 0xfc, 0x34, 0x7e, 0x0f, 0x07, 0x7c, 0x91,
	0xd8, 0xac, 0xa3, 0xf5, 0xfa, 0xfd, 0x4f, 0x2a, 0x8d, 0x3c, 0xd9, 0x24, 0xcb, 0xd5, 0xb4, 0x1b,
	0x87, 0x9c, 0xb2, 0xd6, 0x37, 0x2f, 0xce, 0xf5, 0xd2, 0xd5, 0xb9, 0x5e, 0xcd, 0x4e, 0x71, 0xbb,
	0x4c, 0xed, 0xb7, 0x3f, 0xf4, 0xba, 0x4f, 0xe5, 0xc9, 0x62, 0xdc, 0x98, 0xf0, 0x20, 0x9f, 0x53,
	0xfe, 0xdb, 0x17, 0xd3, 0xd3, 0x3c, 0xd4, 0x44, 0x51, 0x38, 0xdb, 0x01, 0x65, 0xed, 0x6b, 0x0d,
	0x23, 0x93, 0x78, 0x72, 0xf7, 0xe7, 0xe7, 0x7a, 0xe9, 0xaf, 0xe7, 0x7a, 0xf9, 0xc3, 0x9f, 0x36,
	0xc1, 0x5b, 0x03, 0x6e, 0x1e, 0x72, 0x26, 0x43, 0x3c, 0x91, 0xee, 0x72, 0x4e, 0xd4, 0x8f, 0xc0,
	0xbd, 0xa3, 0x7e, 0xdb, 0xfc, 0xd2, 0xea, 0x9b, 0x6d, 0xa5, 0x04, 0x77, 0xa3, 0x18, 0xed, 0x14,
	0x38, 0x47, 0x6c, 0x4a, 0x8e, 0x29, 0x23, 0x53, 0xf5, 0x03, 0x70, 0x67, 0xe8, 0x1a, 0x5f, 0x5b,
	0xfd, 0x8e, 0x52, 0x86, 0x30, 0x8a, 0xd1, 0xa3, 0x02, 0x75, 0x98, 0x5d, 0x01, 0xf5, 0x31, 0xd8,
	0x1a, 0x19, 0xdd, 0xa1, 0xe9, 0x2a, 0x6b, 0xb0, 0x12, 0xc5, 0xe8, 0x9d, 0x02, 0x6f, 0x84, 0x67,
	0x82, 0x48, 0x75, 0x1f, 0x00, 0xb3, 0xdf, 0x31, 0x3a, 0x66, 0xcf, 0xec, 0xbb, 0xca, 0x3a, 0xac,
	0x46, 0x31, 0xaa, 0x14, 0xa8, 0x37, 0xa1, 0xab, 0xef, 0x83, 0xcd, 0x9e, 0xf5, 0xad, 0xe9, 0x28,
	0x1b, 0x70, 0x27, 0x8a, 0xd1, 0x76, 0x81, 0xd9, 0xa3, 0xcf, 0x48, 0xa8, 0x1e, 0x80, 0x07, 0x6d,
	0x6b, 0xe8, 0x3a, 0x56, 0xeb, 0xc8, 0xb5, 0xec, 0xbe, 0xb2, 0x09, 0xf5, 0x28, 0x46, 0xef, 0x16,
	0xb8, 0x6d, 0x2a, 0x64, 0x48, 0xc7, 0x8b, 0x24, 0x28, 0xf5, 0x29, 0x78, 0x68, 0x8f, 0x4c, 0x67,
	0x68, 0x75, 0xbe, 0x72, 0xbd, 0x43, 0xbb, 0xd7, 0x3b, 0xea, 0x5b, 0xee, 0x77, 0xca, 0x16, 0x7c,
	0x1c, 0xc5, 0xe8, 0xbd, 0x42, 0xa7, 0x7d, 0x46, 0x42, 0x41, 0xfd, 0x13, 0x79, 0xc8, 0x83, 0x60,
	0xc1, 0xa8, 0x5c, 0xaa, 0x2e, 0xa8, 0xde, 0xd2, 0xef, 0x0d, 0x1c, 0x7b, 0x60, 0x0f, 0x8d, 0xee,
	0x50, 0xb9, 0x03, 0x0f, 0xa2, 0x18, 0xed, 0xff, 0xaf, 0x52, 0x87, 0x9f, 0x0d, 0x42, 0x3e, 0xe7,
	0x02, 0xcf, 0x84, 0xfa, 0x19, 0x78, 0xf3, 0x15, 0x2d, 0xdb, 0xee, 0x2a, 0x77, 0x21, 0x8a, 0x62,
	0xb4, 0x5b, 0x90, 0xb9, 0xee, 0x1e, 0x70, 0x3e, 0x53, 0x3f, 0x07, 0xca, 0xc8, 0xe8, 0x5a, 0x6d,
	0xc3, 0xb5, 0x1d, 0x6f, 0x64, 0xbb, 0xc9, 0xac, 0xee, 0xc1, 0x5a, 0x14, 0x23, 0xed, 0xf5, 0x19,
	0xd0, 0x29, 0x96, 0x3c, 0x1c, 0x71, 0x99, 0xcc, 0xec, 0x63, 0xf0, 0xc0, 0x70, 0x5a, 0x96, 0x6b,
	0x3a, 0x99, 0x1b, 0x80, 0x5a, 0x14, 0x23, 0x58, 0xe8, 0x32, 0xc2, 0x31, 0x95, 0x24, 0x4c, 0xbd,
	0xbe, 0x00, 0x0f, 0x5f, 0xed, 0x58, 0xd9, 0xdd, 0x87, 0x7b, 0x51, 0x8c, 0xd0, 0xbf, 0x37, 0x66,
	0x86, 0x70, 0xe3, 0x87, 0x5f, 0xb5, 0x52, 0xeb, 0xe9, 0x8b, 0x0b, 0xad, 0xfc, 0xf2, 0x42, 0x2b,
	0xff, 0x79, 0xa1, 0x95, 0x7f, 0xbc, 0xd4, 0x4a, 0x2f, 0x2f, 0xb5, 0xd2, 0xef, 0x97, 0x5a, 0xe9,
	0xfb, 0xbd, 0x7f, 0x5c, 0xfc, 0xf4, 0x45, 0x95, 0x7e, 0x88, 0xa7, 0xa4, 0xf9, 0x2c, 0x7d, 0x5a,
	0xd3, 0xab, 0x3f, 0xde, 0x4a, 0x1f, 0x94, 0x4f, 0xff, 0x0e, 0x00, 0x00, 0xff, 0xff, 0xa6, 0x74,
	0x0b, 0xa9, 0x75, 0x05, 0x00, 0x00,
}

func (this *Params) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Params)
	if !ok {
		that2, ok := that.(Params)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.HistoricalEntries != that1.HistoricalEntries {
		return false
	}
	if this.InitialValEngagementPoints != that1.InitialValEngagementPoints {
		return false
	}
	if len(this.MinDelegationAmounts) != len(that1.MinDelegationAmounts) {
		return false
	}
	for i := range this.MinDelegationAmounts {
		if !this.MinDelegationAmounts[i].Equal(&that1.MinDelegationAmounts[i]) {
			return false
		}
	}
	return true
}
func (m *Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Params) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.MinDelegationAmounts) > 0 {
		for iNdEx := len(m.MinDelegationAmounts) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.MinDelegationAmounts[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintPoe(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x1a
		}
	}
	if m.InitialValEngagementPoints != 0 {
		i = encodeVarintPoe(dAtA, i, uint64(m.InitialValEngagementPoints))
		i--
		dAtA[i] = 0x10
	}
	if m.HistoricalEntries != 0 {
		i = encodeVarintPoe(dAtA, i, uint64(m.HistoricalEntries))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintPoe(dAtA []byte, offset int, v uint64) int {
	offset -= sovPoe(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Params) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.HistoricalEntries != 0 {
		n += 1 + sovPoe(uint64(m.HistoricalEntries))
	}
	if m.InitialValEngagementPoints != 0 {
		n += 1 + sovPoe(uint64(m.InitialValEngagementPoints))
	}
	if len(m.MinDelegationAmounts) > 0 {
		for _, e := range m.MinDelegationAmounts {
			l = e.Size()
			n += 1 + l + sovPoe(uint64(l))
		}
	}
	return n
}

func sovPoe(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozPoe(x uint64) (n int) {
	return sovPoe(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Params) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowPoe
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Params: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Params: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field HistoricalEntries", wireType)
			}
			m.HistoricalEntries = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowPoe
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.HistoricalEntries |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field InitialValEngagementPoints", wireType)
			}
			m.InitialValEngagementPoints = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowPoe
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.InitialValEngagementPoints |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MinDelegationAmounts", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowPoe
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthPoe
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthPoe
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.MinDelegationAmounts = append(m.MinDelegationAmounts, types.Coin{})
			if err := m.MinDelegationAmounts[len(m.MinDelegationAmounts)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipPoe(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthPoe
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipPoe(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowPoe
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowPoe
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowPoe
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthPoe
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupPoe
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthPoe
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthPoe        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowPoe          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupPoe = fmt.Errorf("proto: unexpected end of group")
)

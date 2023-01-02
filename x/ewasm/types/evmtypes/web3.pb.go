// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: confio/ewasm/v1beta1/web3.proto

package evmtypes

import (
	fmt "fmt"
	_ "github.com/cosmos/gogoproto/gogoproto"
	proto "github.com/gogo/protobuf/proto"
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

type ExtensionOptionsWeb3Tx struct {
	// typed data chain id used only in EIP712 Domain and should match
	// Ethereum network ID in a Web3 provider (e.g. Metamask).
	TypedDataChainID uint64 `protobuf:"varint,1,opt,name=typed_data_chain_id,json=typedDataChainId,proto3" json:"typedDataChainID,omitempty"`
	// fee payer is an account address for the fee payer. It will be validated
	// during EIP712 signature checking.
	FeePayer string `protobuf:"bytes,2,opt,name=fee_payer,json=feePayer,proto3" json:"feePayer,omitempty"`
	// fee payer sig is a signature data from the fee paying account,
	// allows to perform fee delegation when using EIP712 Domain.
	FeePayerSig []byte `protobuf:"bytes,3,opt,name=fee_payer_sig,json=feePayerSig,proto3" json:"feePayerSig,omitempty"`
}

func (m *ExtensionOptionsWeb3Tx) Reset()         { *m = ExtensionOptionsWeb3Tx{} }
func (m *ExtensionOptionsWeb3Tx) String() string { return proto.CompactTextString(m) }
func (*ExtensionOptionsWeb3Tx) ProtoMessage()    {}
func (*ExtensionOptionsWeb3Tx) Descriptor() ([]byte, []int) {
	return fileDescriptor_66c8041674bc1674, []int{0}
}
func (m *ExtensionOptionsWeb3Tx) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ExtensionOptionsWeb3Tx) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ExtensionOptionsWeb3Tx.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ExtensionOptionsWeb3Tx) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExtensionOptionsWeb3Tx.Merge(m, src)
}
func (m *ExtensionOptionsWeb3Tx) XXX_Size() int {
	return m.Size()
}
func (m *ExtensionOptionsWeb3Tx) XXX_DiscardUnknown() {
	xxx_messageInfo_ExtensionOptionsWeb3Tx.DiscardUnknown(m)
}

var xxx_messageInfo_ExtensionOptionsWeb3Tx proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ExtensionOptionsWeb3Tx)(nil), "confio.ewasm.v1beta1.ExtensionOptionsWeb3Tx")
}

func init() { proto.RegisterFile("confio/ewasm/v1beta1/web3.proto", fileDescriptor_66c8041674bc1674) }

var fileDescriptor_66c8041674bc1674 = []byte{
	// 317 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x90, 0x3f, 0x4f, 0xf2, 0x50,
	0x14, 0xc6, 0x7b, 0xdf, 0x97, 0x18, 0xa9, 0x9a, 0x90, 0x8a, 0x04, 0x19, 0xee, 0x25, 0x4e, 0x0c,
	0xa6, 0x37, 0xd8, 0xcd, 0xc4, 0xa5, 0xe2, 0xc0, 0xa4, 0x51, 0x12, 0x13, 0x97, 0xe6, 0x96, 0x1e,
	0x2e, 0x77, 0x68, 0x6f, 0x43, 0x8f, 0xfc, 0xf9, 0x06, 0x8e, 0x7e, 0x04, 0x3f, 0x8e, 0x23, 0xa3,
	0x53, 0x63, 0xca, 0xc6, 0xee, 0x6e, 0x5a, 0xc0, 0x34, 0x6c, 0x27, 0xbf, 0xe7, 0xf7, 0x0c, 0xe7,
	0x31, 0xd9, 0x50, 0x47, 0x23, 0xa5, 0x39, 0xcc, 0x44, 0x12, 0xf2, 0x69, 0xd7, 0x07, 0x14, 0x5d,
	0x3e, 0x03, 0xdf, 0xb1, 0xe3, 0x89, 0x46, 0x6d, 0xd5, 0x37, 0x82, 0x5d, 0x08, 0xf6, 0x56, 0x68,
	0xd5, 0xa5, 0x96, 0xba, 0x10, 0x78, 0x7e, 0x6d, 0xdc, 0x8b, 0x1f, 0x62, 0x36, 0xee, 0xe6, 0x08,
	0x51, 0xa2, 0x74, 0x74, 0x1f, 0xa3, 0xd2, 0x51, 0xf2, 0x0c, 0xbe, 0x33, 0x98, 0x5b, 0xc2, 0x3c,
	0xc5, 0x45, 0x0c, 0x81, 0x17, 0x08, 0x14, 0xde, 0x70, 0x2c, 0x54, 0xe4, 0xa9, 0xa0, 0x49, 0xda,
	0xa4, 0x53, 0x71, 0xaf, 0xb2, 0x94, 0xd5, 0x06, 0x79, 0xdc, 0x13, 0x28, 0x6e, 0xf3, 0xb0, 0xdf,
	0x5b, 0xa7, 0xac, 0x85, 0x7b, 0xec, 0x52, 0x87, 0x0a, 0x21, 0x8c, 0x71, 0xf1, 0x58, 0xdb, 0xcb,
	0x02, 0xcb, 0x31, 0xab, 0x23, 0x00, 0x2f, 0x16, 0x0b, 0x98, 0x34, 0xff, 0xb5, 0x49, 0xa7, 0xea,
	0x36, 0xd6, 0x29, 0xb3, 0x46, 0x00, 0x0f, 0x39, 0x2b, 0x95, 0x0f, 0x77, 0xcc, 0xba, 0x31, 0x4f,
	0xfe, 0x4a, 0x5e, 0xa2, 0x64, 0xf3, 0x7f, 0x9b, 0x74, 0x8e, 0xdd, 0xf3, 0x75, 0xca, 0xce, 0x76,
	0xd2, 0x93, 0x92, 0xa5, 0xee, 0x51, 0x09, 0x5f, 0x57, 0xde, 0x3e, 0x98, 0xe1, 0xf6, 0x3f, 0x33,
	0x4a, 0x96, 0x19, 0x25, 0xdf, 0x19, 0x25, 0xef, 0x2b, 0x6a, 0x2c, 0x57, 0xd4, 0xf8, 0x5a, 0x51,
	0xe3, 0x85, 0x4b, 0x85, 0xe3, 0x57, 0xdf, 0x1e, 0xea, 0x90, 0x6f, 0x97, 0x46, 0x39, 0x11, 0x01,
	0xf0, 0xf9, 0x76, 0xf2, 0xfc, 0x8d, 0x84, 0xc3, 0x34, 0x2c, 0x0e, 0xff, 0xa0, 0x58, 0xd2, 0xf9,
	0x0d, 0x00, 0x00, 0xff, 0xff, 0xa5, 0x79, 0x0e, 0x70, 0x98, 0x01, 0x00, 0x00,
}

func (m *ExtensionOptionsWeb3Tx) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ExtensionOptionsWeb3Tx) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ExtensionOptionsWeb3Tx) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.FeePayerSig) > 0 {
		i -= len(m.FeePayerSig)
		copy(dAtA[i:], m.FeePayerSig)
		i = encodeVarintWeb3(dAtA, i, uint64(len(m.FeePayerSig)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.FeePayer) > 0 {
		i -= len(m.FeePayer)
		copy(dAtA[i:], m.FeePayer)
		i = encodeVarintWeb3(dAtA, i, uint64(len(m.FeePayer)))
		i--
		dAtA[i] = 0x12
	}
	if m.TypedDataChainID != 0 {
		i = encodeVarintWeb3(dAtA, i, uint64(m.TypedDataChainID))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintWeb3(dAtA []byte, offset int, v uint64) int {
	offset -= sovWeb3(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ExtensionOptionsWeb3Tx) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.TypedDataChainID != 0 {
		n += 1 + sovWeb3(uint64(m.TypedDataChainID))
	}
	l = len(m.FeePayer)
	if l > 0 {
		n += 1 + l + sovWeb3(uint64(l))
	}
	l = len(m.FeePayerSig)
	if l > 0 {
		n += 1 + l + sovWeb3(uint64(l))
	}
	return n
}

func sovWeb3(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozWeb3(x uint64) (n int) {
	return sovWeb3(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ExtensionOptionsWeb3Tx) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowWeb3
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
			return fmt.Errorf("proto: ExtensionOptionsWeb3Tx: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ExtensionOptionsWeb3Tx: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TypedDataChainID", wireType)
			}
			m.TypedDataChainID = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWeb3
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TypedDataChainID |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FeePayer", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWeb3
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthWeb3
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthWeb3
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.FeePayer = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FeePayerSig", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowWeb3
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthWeb3
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthWeb3
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.FeePayerSig = append(m.FeePayerSig[:0], dAtA[iNdEx:postIndex]...)
			if m.FeePayerSig == nil {
				m.FeePayerSig = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipWeb3(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthWeb3
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
func skipWeb3(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowWeb3
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
					return 0, ErrIntOverflowWeb3
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
					return 0, ErrIntOverflowWeb3
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
				return 0, ErrInvalidLengthWeb3
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupWeb3
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthWeb3
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthWeb3        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowWeb3          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupWeb3 = fmt.Errorf("proto: unexpected end of group")
)

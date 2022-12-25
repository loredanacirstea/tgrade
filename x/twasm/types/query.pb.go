// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: confio/twasm/v1beta1/query.proto

package types

import (
	context "context"
	fmt "fmt"
	_ "github.com/CosmWasm/wasmd/x/wasm/types"
	_ "github.com/cosmos/cosmos-sdk/types/query"
	_ "github.com/cosmos/gogoproto/gogoproto"
	grpc1 "github.com/gogo/protobuf/grpc"
	proto "github.com/gogo/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

// QueryPrivilegedContractsResponse is the request type for the
// Query/PrivilegedContracts RPC method
type QueryPrivilegedContractsRequest struct {
}

func (m *QueryPrivilegedContractsRequest) Reset()         { *m = QueryPrivilegedContractsRequest{} }
func (m *QueryPrivilegedContractsRequest) String() string { return proto.CompactTextString(m) }
func (*QueryPrivilegedContractsRequest) ProtoMessage()    {}
func (*QueryPrivilegedContractsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dcfe179625ad95e, []int{0}
}
func (m *QueryPrivilegedContractsRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryPrivilegedContractsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryPrivilegedContractsRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryPrivilegedContractsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryPrivilegedContractsRequest.Merge(m, src)
}
func (m *QueryPrivilegedContractsRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryPrivilegedContractsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryPrivilegedContractsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryPrivilegedContractsRequest proto.InternalMessageInfo

// QueryPrivilegedContractsResponse is the response type for the
// Query/PrivilegedContracts RPC method
type QueryPrivilegedContractsResponse struct {
	// contracts are a set of contract addresses
	Contracts []string `protobuf:"bytes,1,rep,name=contracts,proto3" json:"contracts,omitempty"`
}

func (m *QueryPrivilegedContractsResponse) Reset()         { *m = QueryPrivilegedContractsResponse{} }
func (m *QueryPrivilegedContractsResponse) String() string { return proto.CompactTextString(m) }
func (*QueryPrivilegedContractsResponse) ProtoMessage()    {}
func (*QueryPrivilegedContractsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dcfe179625ad95e, []int{1}
}
func (m *QueryPrivilegedContractsResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryPrivilegedContractsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryPrivilegedContractsResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryPrivilegedContractsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryPrivilegedContractsResponse.Merge(m, src)
}
func (m *QueryPrivilegedContractsResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryPrivilegedContractsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryPrivilegedContractsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryPrivilegedContractsResponse proto.InternalMessageInfo

func (m *QueryPrivilegedContractsResponse) GetContracts() []string {
	if m != nil {
		return m.Contracts
	}
	return nil
}

// QueryContractsByPrivilegeTypeRequest is the request type for the
// Query/ContractsByPrivilegeType RPC method
type QueryContractsByPrivilegeTypeRequest struct {
	PrivilegeType string `protobuf:"bytes,1,opt,name=privilege_type,json=privilegeType,proto3" json:"privilege_type,omitempty"`
}

func (m *QueryContractsByPrivilegeTypeRequest) Reset()         { *m = QueryContractsByPrivilegeTypeRequest{} }
func (m *QueryContractsByPrivilegeTypeRequest) String() string { return proto.CompactTextString(m) }
func (*QueryContractsByPrivilegeTypeRequest) ProtoMessage()    {}
func (*QueryContractsByPrivilegeTypeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dcfe179625ad95e, []int{2}
}
func (m *QueryContractsByPrivilegeTypeRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryContractsByPrivilegeTypeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryContractsByPrivilegeTypeRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryContractsByPrivilegeTypeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryContractsByPrivilegeTypeRequest.Merge(m, src)
}
func (m *QueryContractsByPrivilegeTypeRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryContractsByPrivilegeTypeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryContractsByPrivilegeTypeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryContractsByPrivilegeTypeRequest proto.InternalMessageInfo

func (m *QueryContractsByPrivilegeTypeRequest) GetPrivilegeType() string {
	if m != nil {
		return m.PrivilegeType
	}
	return ""
}

// QueryContractsByPrivilegeTypeResponse is the response type for the
// Query/ContractsByPrivilegeType RPC method
type QueryContractsByPrivilegeTypeResponse struct {
	// contracts are a set of contract addresses
	Contracts []string `protobuf:"bytes,1,rep,name=contracts,proto3" json:"contracts,omitempty"`
}

func (m *QueryContractsByPrivilegeTypeResponse) Reset()         { *m = QueryContractsByPrivilegeTypeResponse{} }
func (m *QueryContractsByPrivilegeTypeResponse) String() string { return proto.CompactTextString(m) }
func (*QueryContractsByPrivilegeTypeResponse) ProtoMessage()    {}
func (*QueryContractsByPrivilegeTypeResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1dcfe179625ad95e, []int{3}
}
func (m *QueryContractsByPrivilegeTypeResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryContractsByPrivilegeTypeResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryContractsByPrivilegeTypeResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryContractsByPrivilegeTypeResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryContractsByPrivilegeTypeResponse.Merge(m, src)
}
func (m *QueryContractsByPrivilegeTypeResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryContractsByPrivilegeTypeResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryContractsByPrivilegeTypeResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryContractsByPrivilegeTypeResponse proto.InternalMessageInfo

func (m *QueryContractsByPrivilegeTypeResponse) GetContracts() []string {
	if m != nil {
		return m.Contracts
	}
	return nil
}

func init() {
	proto.RegisterType((*QueryPrivilegedContractsRequest)(nil), "confio.twasm.v1beta1.QueryPrivilegedContractsRequest")
	proto.RegisterType((*QueryPrivilegedContractsResponse)(nil), "confio.twasm.v1beta1.QueryPrivilegedContractsResponse")
	proto.RegisterType((*QueryContractsByPrivilegeTypeRequest)(nil), "confio.twasm.v1beta1.QueryContractsByPrivilegeTypeRequest")
	proto.RegisterType((*QueryContractsByPrivilegeTypeResponse)(nil), "confio.twasm.v1beta1.QueryContractsByPrivilegeTypeResponse")
}

func init() { proto.RegisterFile("confio/twasm/v1beta1/query.proto", fileDescriptor_1dcfe179625ad95e) }

var fileDescriptor_1dcfe179625ad95e = []byte{
	// 403 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x48, 0xce, 0xcf, 0x4b,
	0xcb, 0xcc, 0xd7, 0x2f, 0x29, 0x4f, 0x2c, 0xce, 0xd5, 0x2f, 0x33, 0x4c, 0x4a, 0x2d, 0x49, 0x34,
	0xd4, 0x2f, 0x2c, 0x4d, 0x2d, 0xaa, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x12, 0x81, 0xa8,
	0xd0, 0x03, 0xab, 0xd0, 0x83, 0xaa, 0x90, 0x12, 0x49, 0xcf, 0x4f, 0xcf, 0x07, 0x2b, 0xd0, 0x07,
	0xb1, 0x20, 0x6a, 0xa5, 0x64, 0x92, 0xf3, 0x8b, 0x73, 0xc1, 0x26, 0x41, 0x8d, 0xd3, 0x2f, 0xa9,
	0x2c, 0x48, 0x2d, 0x86, 0xc9, 0xa6, 0xe7, 0xe7, 0xa7, 0xe7, 0xa4, 0xea, 0x27, 0x16, 0x64, 0xea,
	0x27, 0xe6, 0xe5, 0xe5, 0x97, 0x24, 0x96, 0x64, 0xe6, 0xe7, 0xc1, 0x64, 0xb5, 0x40, 0x7a, 0xf3,
	0x8b, 0xf5, 0x93, 0x12, 0x8b, 0x53, 0x21, 0x0e, 0x80, 0x3b, 0xa7, 0x20, 0x31, 0x3d, 0x33, 0x0f,
	0xac, 0x18, 0xa2, 0x56, 0x49, 0x91, 0x4b, 0x3e, 0x10, 0xa4, 0x22, 0xa0, 0x28, 0xb3, 0x2c, 0x33,
	0x27, 0x35, 0x3d, 0x35, 0xc5, 0x39, 0x3f, 0xaf, 0xa4, 0x28, 0x31, 0xb9, 0xa4, 0x38, 0x28, 0xb5,
	0xb0, 0x34, 0xb5, 0xb8, 0x44, 0xc9, 0x81, 0x4b, 0x01, 0xb7, 0x92, 0xe2, 0x82, 0xfc, 0xbc, 0xe2,
	0x54, 0x21, 0x19, 0x2e, 0xce, 0x64, 0x98, 0xa0, 0x04, 0xa3, 0x02, 0xb3, 0x06, 0x67, 0x10, 0x42,
	0x40, 0xc9, 0x97, 0x4b, 0x05, 0x6c, 0x02, 0x5c, 0x9f, 0x13, 0xc2, 0xb0, 0x90, 0xca, 0x82, 0x54,
	0xa8, 0x4d, 0x42, 0xaa, 0x5c, 0x7c, 0x05, 0x30, 0xf1, 0x78, 0x90, 0x7f, 0x25, 0x18, 0x15, 0x18,
	0x35, 0x38, 0x83, 0x78, 0x0b, 0x90, 0x55, 0x2b, 0xb9, 0x72, 0xa9, 0x12, 0x30, 0x8e, 0x18, 0x57,
	0x19, 0xcd, 0x61, 0xe6, 0x62, 0x05, 0x9b, 0x23, 0xb4, 0x83, 0x91, 0x4b, 0x18, 0x8b, 0xef, 0x84,
	0x4c, 0xf5, 0xb0, 0xc5, 0x98, 0x1e, 0x81, 0x00, 0x93, 0x32, 0x23, 0x55, 0x1b, 0xc4, 0xb9, 0x4a,
	0x46, 0x4d, 0x97, 0x9f, 0x4c, 0x66, 0xd2, 0x11, 0xd2, 0xd2, 0x2f, 0x49, 0x2f, 0x4a, 0x4c, 0x49,
	0x45, 0x4b, 0x4a, 0x70, 0x97, 0xeb, 0xc3, 0x83, 0x23, 0x45, 0xe8, 0x3a, 0x23, 0x97, 0x04, 0xae,
	0x70, 0x10, 0xb2, 0xc2, 0xe3, 0x10, 0x02, 0x71, 0x21, 0x65, 0x4d, 0x96, 0x5e, 0xa8, 0x4f, 0x9c,
	0xc0, 0x3e, 0xb1, 0x11, 0xb2, 0x22, 0xda, 0x27, 0xfa, 0xd5, 0xa8, 0x31, 0x5f, 0xeb, 0xe4, 0x70,
	0xe2, 0x91, 0x1c, 0xe3, 0x85, 0x47, 0x72, 0x8c, 0x0f, 0x1e, 0xc9, 0x31, 0x4e, 0x78, 0x2c, 0xc7,
	0x70, 0xe1, 0xb1, 0x1c, 0xc3, 0x8d, 0xc7, 0x72, 0x0c, 0x51, 0x6a, 0xe9, 0x99, 0x25, 0x19, 0xa5,
	0x49, 0x7a, 0xc9, 0xf9, 0xb9, 0xfa, 0xb0, 0x4c, 0x07, 0xb1, 0xa6, 0x02, 0x6a, 0x11, 0x38, 0xaf,
	0x24, 0xb1, 0x81, 0x93, 0xb8, 0x31, 0x20, 0x00, 0x00, 0xff, 0xff, 0x8c, 0x07, 0x61, 0xc0, 0x9a,
	0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type QueryClient interface {
	// PrivilegedContracts returns all privileged contracts
	PrivilegedContracts(ctx context.Context, in *QueryPrivilegedContractsRequest, opts ...grpc.CallOption) (*QueryPrivilegedContractsResponse, error)
	// ContractsByPrivilegeType returns all contracts that have registered for the
	// privilege type
	ContractsByPrivilegeType(ctx context.Context, in *QueryContractsByPrivilegeTypeRequest, opts ...grpc.CallOption) (*QueryContractsByPrivilegeTypeResponse, error)
}

type queryClient struct {
	cc grpc1.ClientConn
}

func NewQueryClient(cc grpc1.ClientConn) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) PrivilegedContracts(ctx context.Context, in *QueryPrivilegedContractsRequest, opts ...grpc.CallOption) (*QueryPrivilegedContractsResponse, error) {
	out := new(QueryPrivilegedContractsResponse)
	err := c.cc.Invoke(ctx, "/confio.twasm.v1beta1.Query/PrivilegedContracts", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) ContractsByPrivilegeType(ctx context.Context, in *QueryContractsByPrivilegeTypeRequest, opts ...grpc.CallOption) (*QueryContractsByPrivilegeTypeResponse, error) {
	out := new(QueryContractsByPrivilegeTypeResponse)
	err := c.cc.Invoke(ctx, "/confio.twasm.v1beta1.Query/ContractsByPrivilegeType", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
type QueryServer interface {
	// PrivilegedContracts returns all privileged contracts
	PrivilegedContracts(context.Context, *QueryPrivilegedContractsRequest) (*QueryPrivilegedContractsResponse, error)
	// ContractsByPrivilegeType returns all contracts that have registered for the
	// privilege type
	ContractsByPrivilegeType(context.Context, *QueryContractsByPrivilegeTypeRequest) (*QueryContractsByPrivilegeTypeResponse, error)
}

// UnimplementedQueryServer can be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (*UnimplementedQueryServer) PrivilegedContracts(ctx context.Context, req *QueryPrivilegedContractsRequest) (*QueryPrivilegedContractsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PrivilegedContracts not implemented")
}
func (*UnimplementedQueryServer) ContractsByPrivilegeType(ctx context.Context, req *QueryContractsByPrivilegeTypeRequest) (*QueryContractsByPrivilegeTypeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ContractsByPrivilegeType not implemented")
}

func RegisterQueryServer(s grpc1.Server, srv QueryServer) {
	s.RegisterService(&_Query_serviceDesc, srv)
}

func _Query_PrivilegedContracts_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryPrivilegedContractsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).PrivilegedContracts(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/confio.twasm.v1beta1.Query/PrivilegedContracts",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).PrivilegedContracts(ctx, req.(*QueryPrivilegedContractsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_ContractsByPrivilegeType_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryContractsByPrivilegeTypeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).ContractsByPrivilegeType(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/confio.twasm.v1beta1.Query/ContractsByPrivilegeType",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).ContractsByPrivilegeType(ctx, req.(*QueryContractsByPrivilegeTypeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Query_serviceDesc = grpc.ServiceDesc{
	ServiceName: "confio.twasm.v1beta1.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PrivilegedContracts",
			Handler:    _Query_PrivilegedContracts_Handler,
		},
		{
			MethodName: "ContractsByPrivilegeType",
			Handler:    _Query_ContractsByPrivilegeType_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "confio/twasm/v1beta1/query.proto",
}

func (m *QueryPrivilegedContractsRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryPrivilegedContractsRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryPrivilegedContractsRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func (m *QueryPrivilegedContractsResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryPrivilegedContractsResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryPrivilegedContractsResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Contracts) > 0 {
		for iNdEx := len(m.Contracts) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Contracts[iNdEx])
			copy(dAtA[i:], m.Contracts[iNdEx])
			i = encodeVarintQuery(dAtA, i, uint64(len(m.Contracts[iNdEx])))
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *QueryContractsByPrivilegeTypeRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryContractsByPrivilegeTypeRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryContractsByPrivilegeTypeRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.PrivilegeType) > 0 {
		i -= len(m.PrivilegeType)
		copy(dAtA[i:], m.PrivilegeType)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.PrivilegeType)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *QueryContractsByPrivilegeTypeResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryContractsByPrivilegeTypeResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryContractsByPrivilegeTypeResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Contracts) > 0 {
		for iNdEx := len(m.Contracts) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Contracts[iNdEx])
			copy(dAtA[i:], m.Contracts[iNdEx])
			i = encodeVarintQuery(dAtA, i, uint64(len(m.Contracts[iNdEx])))
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintQuery(dAtA []byte, offset int, v uint64) int {
	offset -= sovQuery(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *QueryPrivilegedContractsRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func (m *QueryPrivilegedContractsResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Contracts) > 0 {
		for _, s := range m.Contracts {
			l = len(s)
			n += 1 + l + sovQuery(uint64(l))
		}
	}
	return n
}

func (m *QueryContractsByPrivilegeTypeRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.PrivilegeType)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryContractsByPrivilegeTypeResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Contracts) > 0 {
		for _, s := range m.Contracts {
			l = len(s)
			n += 1 + l + sovQuery(uint64(l))
		}
	}
	return n
}

func sovQuery(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozQuery(x uint64) (n int) {
	return sovQuery(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *QueryPrivilegedContractsRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
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
			return fmt.Errorf("proto: QueryPrivilegedContractsRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryPrivilegedContractsRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
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
func (m *QueryPrivilegedContractsResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
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
			return fmt.Errorf("proto: QueryPrivilegedContractsResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryPrivilegedContractsResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Contracts", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
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
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Contracts = append(m.Contracts, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
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
func (m *QueryContractsByPrivilegeTypeRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
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
			return fmt.Errorf("proto: QueryContractsByPrivilegeTypeRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryContractsByPrivilegeTypeRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PrivilegeType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
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
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PrivilegeType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
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
func (m *QueryContractsByPrivilegeTypeResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
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
			return fmt.Errorf("proto: QueryContractsByPrivilegeTypeResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryContractsByPrivilegeTypeResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Contracts", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
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
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Contracts = append(m.Contracts, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
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
func skipQuery(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowQuery
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
					return 0, ErrIntOverflowQuery
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
					return 0, ErrIntOverflowQuery
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
				return 0, ErrInvalidLengthQuery
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupQuery
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthQuery
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthQuery        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowQuery          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupQuery = fmt.Errorf("proto: unexpected end of group")
)

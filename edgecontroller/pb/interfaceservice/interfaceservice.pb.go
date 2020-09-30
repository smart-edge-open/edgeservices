// SPDX-License-Identifier: Apache-2.0
// Copyright © 2020 Intel Corporation

package interfaceservice

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Port_InterfaceDriver int32

const (
	Port_NONE      Port_InterfaceDriver = 0
	Port_KERNEL    Port_InterfaceDriver = 1
	Port_USERSPACE Port_InterfaceDriver = 2
)

var Port_InterfaceDriver_name = map[int32]string{
	0: "NONE",
	1: "KERNEL",
	2: "USERSPACE",
}

var Port_InterfaceDriver_value = map[string]int32{
	"NONE":      0,
	"KERNEL":    1,
	"USERSPACE": 2,
}

func (x Port_InterfaceDriver) String() string {
	return proto.EnumName(Port_InterfaceDriver_name, int32(x))
}

func (Port_InterfaceDriver) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_d5273313c90a13ab, []int{0, 0}
}

// Port defines a network interface available on the host.
// Port are typically kernel interfaces by default, and can be changed if
// the caller wishes to do so.
type Port struct {
	Pci                  string               `protobuf:"bytes,1,opt,name=pci,proto3" json:"pci,omitempty"`
	Driver               Port_InterfaceDriver `protobuf:"varint,2,opt,name=driver,proto3,enum=openness.interfaceservice.Port_InterfaceDriver" json:"driver,omitempty"`
	Bridge               string               `protobuf:"bytes,3,opt,name=bridge,proto3" json:"bridge,omitempty"`
	MacAddress           string               `protobuf:"bytes,4,opt,name=macAddress,proto3" json:"macAddress,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *Port) Reset()         { *m = Port{} }
func (m *Port) String() string { return proto.CompactTextString(m) }
func (*Port) ProtoMessage()    {}
func (*Port) Descriptor() ([]byte, []int) {
	return fileDescriptor_d5273313c90a13ab, []int{0}
}

func (m *Port) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Port.Unmarshal(m, b)
}
func (m *Port) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Port.Marshal(b, m, deterministic)
}
func (m *Port) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Port.Merge(m, src)
}
func (m *Port) XXX_Size() int {
	return xxx_messageInfo_Port.Size(m)
}
func (m *Port) XXX_DiscardUnknown() {
	xxx_messageInfo_Port.DiscardUnknown(m)
}

var xxx_messageInfo_Port proto.InternalMessageInfo

func (m *Port) GetPci() string {
	if m != nil {
		return m.Pci
	}
	return ""
}

func (m *Port) GetDriver() Port_InterfaceDriver {
	if m != nil {
		return m.Driver
	}
	return Port_NONE
}

func (m *Port) GetBridge() string {
	if m != nil {
		return m.Bridge
	}
	return ""
}

func (m *Port) GetMacAddress() string {
	if m != nil {
		return m.MacAddress
	}
	return ""
}

type Ports struct {
	Ports                []*Port  `protobuf:"bytes,1,rep,name=ports,proto3" json:"ports,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ports) Reset()         { *m = Ports{} }
func (m *Ports) String() string { return proto.CompactTextString(m) }
func (*Ports) ProtoMessage()    {}
func (*Ports) Descriptor() ([]byte, []int) {
	return fileDescriptor_d5273313c90a13ab, []int{1}
}

func (m *Ports) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ports.Unmarshal(m, b)
}
func (m *Ports) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ports.Marshal(b, m, deterministic)
}
func (m *Ports) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ports.Merge(m, src)
}
func (m *Ports) XXX_Size() int {
	return xxx_messageInfo_Ports.Size(m)
}
func (m *Ports) XXX_DiscardUnknown() {
	xxx_messageInfo_Ports.DiscardUnknown(m)
}

var xxx_messageInfo_Ports proto.InternalMessageInfo

func (m *Ports) GetPorts() []*Port {
	if m != nil {
		return m.Ports
	}
	return nil
}

func init() {
	proto.RegisterEnum("openness.interfaceservice.Port_InterfaceDriver", Port_InterfaceDriver_name, Port_InterfaceDriver_value)
	proto.RegisterType((*Port)(nil), "openness.interfaceservice.Port")
	proto.RegisterType((*Ports)(nil), "openness.interfaceservice.Ports")
}

func init() { proto.RegisterFile("interfaceservice.proto", fileDescriptor_d5273313c90a13ab) }

var fileDescriptor_d5273313c90a13ab = []byte{
	// 329 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x90, 0xc1, 0x4a, 0xf3, 0x40,
	0x14, 0x85, 0x9b, 0xa6, 0x0d, 0x7f, 0xef, 0x8f, 0x1a, 0xee, 0xa2, 0xc4, 0x0a, 0x1a, 0x82, 0x48,
	0x57, 0x13, 0xa8, 0xe8, 0x52, 0x88, 0x36, 0x14, 0x51, 0x6a, 0x49, 0x71, 0xe3, 0x2e, 0x99, 0xdc,
	0xa6, 0x01, 0xdb, 0x09, 0x33, 0xd3, 0x82, 0x8f, 0xe9, 0x23, 0xf8, 0x26, 0x92, 0xa4, 0x15, 0x29,
	0x94, 0x2e, 0xdc, 0xdd, 0xb9, 0x73, 0xce, 0x77, 0x66, 0x0e, 0x74, 0xf3, 0xa5, 0x26, 0x39, 0x8b,
	0x39, 0x29, 0x92, 0xeb, 0x9c, 0x13, 0x2b, 0xa4, 0xd0, 0x02, 0x4f, 0x45, 0x41, 0xcb, 0x25, 0x29,
	0xc5, 0x76, 0x05, 0xbd, 0xb3, 0x4c, 0x88, 0xec, 0x9d, 0xfc, 0x4a, 0x98, 0xac, 0x66, 0x3e, 0x2d,
	0x0a, 0xfd, 0x51, 0xfb, 0xbc, 0x4f, 0x03, 0x5a, 0x13, 0x21, 0x35, 0xda, 0x60, 0x16, 0x3c, 0x77,
	0x0c, 0xd7, 0xe8, 0x77, 0xa2, 0x72, 0xc4, 0x11, 0x58, 0xa9, 0xcc, 0xd7, 0x24, 0x9d, 0xa6, 0x6b,
	0xf4, 0x8f, 0x07, 0x3e, 0xdb, 0x9b, 0xc1, 0x4a, 0x04, 0x7b, 0xdc, 0x6e, 0x87, 0x95, 0x2d, 0xda,
	0xd8, 0xb1, 0x0b, 0x56, 0x22, 0xf3, 0x34, 0x23, 0xc7, 0xac, 0xe8, 0x9b, 0x13, 0x9e, 0x03, 0x2c,
	0x62, 0x1e, 0xa4, 0xa9, 0x24, 0xa5, 0x9c, 0x56, 0x75, 0xf7, 0x6b, 0xe3, 0xdd, 0xc2, 0xc9, 0x0e,
	0x12, 0xff, 0x41, 0x6b, 0xfc, 0x32, 0x0e, 0xed, 0x06, 0x02, 0x58, 0x4f, 0x61, 0x34, 0x0e, 0x9f,
	0x6d, 0x03, 0x8f, 0xa0, 0xf3, 0x3a, 0x0d, 0xa3, 0xe9, 0x24, 0x78, 0x08, 0xed, 0xa6, 0x77, 0x07,
	0xed, 0xf2, 0x3d, 0x0a, 0x6f, 0xa0, 0x5d, 0x94, 0x83, 0x63, 0xb8, 0x66, 0xff, 0xff, 0xe0, 0xe2,
	0xc0, 0x07, 0xa2, 0x5a, 0x3d, 0xf8, 0x32, 0xc0, 0xfe, 0x09, 0x9e, 0xd6, 0x02, 0x0c, 0xc0, 0x1c,
	0x91, 0xc6, 0x2e, 0xab, 0xdb, 0x64, 0xdb, 0x36, 0x59, 0x58, 0xb6, 0xd9, 0x73, 0x0f, 0xb0, 0x95,
	0xd7, 0xc0, 0x21, 0x58, 0x81, 0xd6, 0x31, 0x9f, 0xe3, 0x41, 0x75, 0x6f, 0x4f, 0x4e, 0x4d, 0x19,
	0xd2, 0x5f, 0x29, 0xf7, 0x57, 0x6f, 0x97, 0x59, 0xae, 0xe7, 0xab, 0x84, 0x71, 0xb1, 0xf0, 0x85,
	0xe6, 0x6a, 0x1e, 0x4b, 0xf2, 0x77, 0x39, 0x89, 0x55, 0x39, 0xaf, 0xbf, 0x03, 0x00, 0x00, 0xff,
	0xff, 0x4b, 0xdb, 0x5e, 0x1f, 0x78, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// InterfaceServiceClient is the client API for InterfaceService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type InterfaceServiceClient interface {
	// Get provides a list of ports available on selected host.
	Get(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*Ports, error)
	// Attach triggers operation of attaching an interface to provided bridge.
	// It requires full definition of Ports.
	Attach(ctx context.Context, in *Ports, opts ...grpc.CallOption) (*empty.Empty, error)
	// Detach removes a port from a bridge. It requires PCI only.
	Detach(ctx context.Context, in *Ports, opts ...grpc.CallOption) (*empty.Empty, error)
}

type interfaceServiceClient struct {
	cc *grpc.ClientConn
}

func NewInterfaceServiceClient(cc *grpc.ClientConn) InterfaceServiceClient {
	return &interfaceServiceClient{cc}
}

func (c *interfaceServiceClient) Get(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*Ports, error) {
	out := new(Ports)
	err := c.cc.Invoke(ctx, "/openness.interfaceservice.InterfaceService/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *interfaceServiceClient) Attach(ctx context.Context, in *Ports, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/openness.interfaceservice.InterfaceService/Attach", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *interfaceServiceClient) Detach(ctx context.Context, in *Ports, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/openness.interfaceservice.InterfaceService/Detach", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InterfaceServiceServer is the server API for InterfaceService service.
type InterfaceServiceServer interface {
	// Get provides a list of ports available on selected host.
	Get(context.Context, *empty.Empty) (*Ports, error)
	// Attach triggers operation of attaching an interface to provided bridge.
	// It requires full definition of Ports.
	Attach(context.Context, *Ports) (*empty.Empty, error)
	// Detach removes a port from a bridge. It requires PCI only.
	Detach(context.Context, *Ports) (*empty.Empty, error)
}

func RegisterInterfaceServiceServer(s *grpc.Server, srv InterfaceServiceServer) {
	s.RegisterService(&_InterfaceService_serviceDesc, srv)
}

func _InterfaceService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(empty.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InterfaceServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/openness.interfaceservice.InterfaceService/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InterfaceServiceServer).Get(ctx, req.(*empty.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _InterfaceService_Attach_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Ports)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InterfaceServiceServer).Attach(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/openness.interfaceservice.InterfaceService/Attach",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InterfaceServiceServer).Attach(ctx, req.(*Ports))
	}
	return interceptor(ctx, in, info, handler)
}

func _InterfaceService_Detach_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Ports)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InterfaceServiceServer).Detach(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/openness.interfaceservice.InterfaceService/Detach",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InterfaceServiceServer).Detach(ctx, req.(*Ports))
	}
	return interceptor(ctx, in, info, handler)
}

var _InterfaceService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "openness.interfaceservice.InterfaceService",
	HandlerType: (*InterfaceServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _InterfaceService_Get_Handler,
		},
		{
			MethodName: "Attach",
			Handler:    _InterfaceService_Attach_Handler,
		},
		{
			MethodName: "Detach",
			Handler:    _InterfaceService_Detach_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "interfaceservice.proto",
}

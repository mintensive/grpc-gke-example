// Code generated by protoc-gen-go. DO NOT EDIT.
// source: grpc_gke.proto

/*
Package grpc_gke_example is a generated protocol buffer package.

It is generated from these files:
	grpc_gke.proto

It has these top-level messages:
	PingRequest
	PingReply
*/
package grpc_gke_example

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type PingRequest struct {
}

func (m *PingRequest) Reset()                    { *m = PingRequest{} }
func (m *PingRequest) String() string            { return proto.CompactTextString(m) }
func (*PingRequest) ProtoMessage()               {}
func (*PingRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type PingReply struct {
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
}

func (m *PingReply) Reset()                    { *m = PingReply{} }
func (m *PingReply) String() string            { return proto.CompactTextString(m) }
func (*PingReply) ProtoMessage()               {}
func (*PingReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *PingReply) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func init() {
	proto.RegisterType((*PingRequest)(nil), "GrpcGkeExample.PingRequest")
	proto.RegisterType((*PingReply)(nil), "GrpcGkeExample.PingReply")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for ExampleService service

type ExampleServiceClient interface {
	Ping(ctx context.Context, in *PingRequest, opts ...grpc.CallOption) (*PingReply, error)
}

type exampleServiceClient struct {
	cc *grpc.ClientConn
}

func NewExampleServiceClient(cc *grpc.ClientConn) ExampleServiceClient {
	return &exampleServiceClient{cc}
}

func (c *exampleServiceClient) Ping(ctx context.Context, in *PingRequest, opts ...grpc.CallOption) (*PingReply, error) {
	out := new(PingReply)
	err := grpc.Invoke(ctx, "/GrpcGkeExample.ExampleService/Ping", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for ExampleService service

type ExampleServiceServer interface {
	Ping(context.Context, *PingRequest) (*PingReply, error)
}

func RegisterExampleServiceServer(s *grpc.Server, srv ExampleServiceServer) {
	s.RegisterService(&_ExampleService_serviceDesc, srv)
}

func _ExampleService_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExampleServiceServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/GrpcGkeExample.ExampleService/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExampleServiceServer).Ping(ctx, req.(*PingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _ExampleService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "GrpcGkeExample.ExampleService",
	HandlerType: (*ExampleServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    _ExampleService_Ping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "grpc_gke.proto",
}

func init() { proto.RegisterFile("grpc_gke.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 193 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4b, 0x2f, 0x2a, 0x48,
	0x8e, 0x4f, 0xcf, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x73, 0x2f, 0x2a, 0x48,
	0x76, 0xcf, 0x4e, 0x75, 0xad, 0x48, 0xcc, 0x2d, 0xc8, 0x49, 0x55, 0xe2, 0xe5, 0xe2, 0x0e, 0xc8,
	0xcc, 0x4b, 0x0f, 0x4a, 0x2d, 0x2c, 0x4d, 0x2d, 0x2e, 0x51, 0x52, 0xe5, 0xe2, 0x84, 0x70, 0x0b,
	0x72, 0x2a, 0x85, 0x24, 0xb8, 0xd8, 0x73, 0x53, 0x8b, 0x8b, 0x13, 0xd3, 0x53, 0x25, 0x18, 0x15,
	0x18, 0x35, 0x38, 0x83, 0x60, 0x5c, 0xa3, 0x00, 0x2e, 0x3e, 0xa8, 0x01, 0xc1, 0xa9, 0x45, 0x65,
	0x99, 0xc9, 0xa9, 0x42, 0x76, 0x5c, 0x2c, 0x20, 0x8d, 0x42, 0xd2, 0x7a, 0xa8, 0x16, 0xe8, 0x21,
	0x99, 0x2e, 0x25, 0x89, 0x5d, 0xb2, 0x20, 0xa7, 0xd2, 0x29, 0x8e, 0x4b, 0x3e, 0x39, 0x3f, 0x57,
	0x2f, 0x37, 0x33, 0xaf, 0x24, 0x35, 0xaf, 0x38, 0xb3, 0x2c, 0x55, 0x0f, 0xe6, 0xf0, 0xf8, 0x54,
	0x88, 0x62, 0x27, 0x61, 0x54, 0xcd, 0x01, 0x20, 0xff, 0x04, 0x30, 0x46, 0x09, 0x80, 0x14, 0xea,
	0xa6, 0x67, 0xa7, 0xea, 0x42, 0x15, 0xfe, 0x60, 0x64, 0x5c, 0xc5, 0x84, 0xe6, 0xcf, 0x24, 0x36,
	0xb0, 0xf7, 0x8d, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x57, 0xd3, 0x10, 0xfb, 0x10, 0x01, 0x00,
	0x00,
}
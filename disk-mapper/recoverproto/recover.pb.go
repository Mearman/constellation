// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v4.22.1
// source: disk-mapper/recoverproto/recover.proto

package recoverproto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RecoverMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KmsUri     string `protobuf:"bytes,3,opt,name=kms_uri,json=kmsUri,proto3" json:"kms_uri,omitempty"`
	StorageUri string `protobuf:"bytes,4,opt,name=storage_uri,json=storageUri,proto3" json:"storage_uri,omitempty"`
}

func (x *RecoverMessage) Reset() {
	*x = RecoverMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_disk_mapper_recoverproto_recover_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RecoverMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RecoverMessage) ProtoMessage() {}

func (x *RecoverMessage) ProtoReflect() protoreflect.Message {
	mi := &file_disk_mapper_recoverproto_recover_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RecoverMessage.ProtoReflect.Descriptor instead.
func (*RecoverMessage) Descriptor() ([]byte, []int) {
	return file_disk_mapper_recoverproto_recover_proto_rawDescGZIP(), []int{0}
}

func (x *RecoverMessage) GetKmsUri() string {
	if x != nil {
		return x.KmsUri
	}
	return ""
}

func (x *RecoverMessage) GetStorageUri() string {
	if x != nil {
		return x.StorageUri
	}
	return ""
}

type RecoverResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RecoverResponse) Reset() {
	*x = RecoverResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_disk_mapper_recoverproto_recover_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RecoverResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RecoverResponse) ProtoMessage() {}

func (x *RecoverResponse) ProtoReflect() protoreflect.Message {
	mi := &file_disk_mapper_recoverproto_recover_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RecoverResponse.ProtoReflect.Descriptor instead.
func (*RecoverResponse) Descriptor() ([]byte, []int) {
	return file_disk_mapper_recoverproto_recover_proto_rawDescGZIP(), []int{1}
}

var File_disk_mapper_recoverproto_recover_proto protoreflect.FileDescriptor

var file_disk_mapper_recoverproto_recover_proto_rawDesc = []byte{
	0x0a, 0x26, 0x64, 0x69, 0x73, 0x6b, 0x2d, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2f, 0x72, 0x65,
	0x63, 0x6f, 0x76, 0x65, 0x72, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x72, 0x65, 0x63, 0x6f, 0x76,
	0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4a, 0x0a, 0x0e, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x6b, 0x6d, 0x73, 0x5f,
	0x75, 0x72, 0x69, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6b, 0x6d, 0x73, 0x55, 0x72,
	0x69, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f, 0x75, 0x72, 0x69,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x55,
	0x72, 0x69, 0x22, 0x11, 0x0a, 0x0f, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x4f, 0x0a, 0x03, 0x41, 0x50, 0x49, 0x12, 0x48, 0x0a, 0x07,
	0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x12, 0x1c, 0x2e, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65,
	0x72, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x1a, 0x1d, 0x2e, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x42, 0x5a, 0x40, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x64, 0x67, 0x65, 0x6c, 0x65, 0x73, 0x73, 0x73, 0x79, 0x73,
	0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x65, 0x6c, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x76,
	0x32, 0x2f, 0x64, 0x69, 0x73, 0x6b, 0x2d, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2f, 0x72, 0x65,
	0x63, 0x6f, 0x76, 0x65, 0x72, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_disk_mapper_recoverproto_recover_proto_rawDescOnce sync.Once
	file_disk_mapper_recoverproto_recover_proto_rawDescData = file_disk_mapper_recoverproto_recover_proto_rawDesc
)

func file_disk_mapper_recoverproto_recover_proto_rawDescGZIP() []byte {
	file_disk_mapper_recoverproto_recover_proto_rawDescOnce.Do(func() {
		file_disk_mapper_recoverproto_recover_proto_rawDescData = protoimpl.X.CompressGZIP(file_disk_mapper_recoverproto_recover_proto_rawDescData)
	})
	return file_disk_mapper_recoverproto_recover_proto_rawDescData
}

var file_disk_mapper_recoverproto_recover_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_disk_mapper_recoverproto_recover_proto_goTypes = []interface{}{
	(*RecoverMessage)(nil),  // 0: recoverproto.RecoverMessage
	(*RecoverResponse)(nil), // 1: recoverproto.RecoverResponse
}
var file_disk_mapper_recoverproto_recover_proto_depIdxs = []int32{
	0, // 0: recoverproto.API.Recover:input_type -> recoverproto.RecoverMessage
	1, // 1: recoverproto.API.Recover:output_type -> recoverproto.RecoverResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_disk_mapper_recoverproto_recover_proto_init() }
func file_disk_mapper_recoverproto_recover_proto_init() {
	if File_disk_mapper_recoverproto_recover_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_disk_mapper_recoverproto_recover_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RecoverMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_disk_mapper_recoverproto_recover_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RecoverResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_disk_mapper_recoverproto_recover_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_disk_mapper_recoverproto_recover_proto_goTypes,
		DependencyIndexes: file_disk_mapper_recoverproto_recover_proto_depIdxs,
		MessageInfos:      file_disk_mapper_recoverproto_recover_proto_msgTypes,
	}.Build()
	File_disk_mapper_recoverproto_recover_proto = out.File
	file_disk_mapper_recoverproto_recover_proto_rawDesc = nil
	file_disk_mapper_recoverproto_recover_proto_goTypes = nil
	file_disk_mapper_recoverproto_recover_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// APIClient is the client API for API service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type APIClient interface {
	Recover(ctx context.Context, in *RecoverMessage, opts ...grpc.CallOption) (*RecoverResponse, error)
}

type aPIClient struct {
	cc grpc.ClientConnInterface
}

func NewAPIClient(cc grpc.ClientConnInterface) APIClient {
	return &aPIClient{cc}
}

func (c *aPIClient) Recover(ctx context.Context, in *RecoverMessage, opts ...grpc.CallOption) (*RecoverResponse, error) {
	out := new(RecoverResponse)
	err := c.cc.Invoke(ctx, "/recoverproto.API/Recover", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// APIServer is the server API for API service.
type APIServer interface {
	Recover(context.Context, *RecoverMessage) (*RecoverResponse, error)
}

// UnimplementedAPIServer can be embedded to have forward compatible implementations.
type UnimplementedAPIServer struct {
}

func (*UnimplementedAPIServer) Recover(context.Context, *RecoverMessage) (*RecoverResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Recover not implemented")
}

func RegisterAPIServer(s *grpc.Server, srv APIServer) {
	s.RegisterService(&_API_serviceDesc, srv)
}

func _API_Recover_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RecoverMessage)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).Recover(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/recoverproto.API/Recover",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).Recover(ctx, req.(*RecoverMessage))
	}
	return interceptor(ctx, in, info, handler)
}

var _API_serviceDesc = grpc.ServiceDesc{
	ServiceName: "recoverproto.API",
	HandlerType: (*APIServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Recover",
			Handler:    _API_Recover_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "disk-mapper/recoverproto/recover.proto",
}

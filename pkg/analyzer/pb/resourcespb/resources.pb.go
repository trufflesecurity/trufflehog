// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v4.25.3
// source: resources.proto

package resourcespb

import (
	analyzerpb "github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
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

// Here to make sure the values in the database are uniform.
// Don't ever use this on it's own as it doesn't uniquely identify a type of
// resource.
type ResourceType int32

const (
	ResourceType_INVALID      ResourceType = 0
	ResourceType_PROJECT      ResourceType = 1
	ResourceType_WORKSPACE    ResourceType = 2
	ResourceType_REPOSITORY   ResourceType = 3
	ResourceType_USER         ResourceType = 4
	ResourceType_GIST         ResourceType = 5
	ResourceType_ORGANIZATION ResourceType = 6
	ResourceType_MODEL        ResourceType = 7
	ResourceType_DOMAIN       ResourceType = 8
	ResourceType_TABLE        ResourceType = 9
	ResourceType_ENDPOINT     ResourceType = 10
	ResourceType_DATABASE     ResourceType = 11
	ResourceType_SHOP         ResourceType = 12
)

// Enum value maps for ResourceType.
var (
	ResourceType_name = map[int32]string{
		0:  "INVALID",
		1:  "PROJECT",
		2:  "WORKSPACE",
		3:  "REPOSITORY",
		4:  "USER",
		5:  "GIST",
		6:  "ORGANIZATION",
		7:  "MODEL",
		8:  "DOMAIN",
		9:  "TABLE",
		10: "ENDPOINT",
		11: "DATABASE",
		12: "SHOP",
	}
	ResourceType_value = map[string]int32{
		"INVALID":      0,
		"PROJECT":      1,
		"WORKSPACE":    2,
		"REPOSITORY":   3,
		"USER":         4,
		"GIST":         5,
		"ORGANIZATION": 6,
		"MODEL":        7,
		"DOMAIN":       8,
		"TABLE":        9,
		"ENDPOINT":     10,
		"DATABASE":     11,
		"SHOP":         12,
	}
)

func (x ResourceType) Enum() *ResourceType {
	p := new(ResourceType)
	*p = x
	return p
}

func (x ResourceType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ResourceType) Descriptor() protoreflect.EnumDescriptor {
	return file_resources_proto_enumTypes[0].Descriptor()
}

func (ResourceType) Type() protoreflect.EnumType {
	return &file_resources_proto_enumTypes[0]
}

func (x ResourceType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ResourceType.Descriptor instead.
func (ResourceType) EnumDescriptor() ([]byte, []int) {
	return file_resources_proto_rawDescGZIP(), []int{0}
}

type Resource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResourceType ResourceType          `protobuf:"varint,1,opt,name=resource_type,json=resourceType,proto3,enum=resources.ResourceType" json:"resource_type,omitempty"`
	SecretType   analyzerpb.SecretType `protobuf:"varint,2,opt,name=secret_type,json=secretType,proto3,enum=analyzer.SecretType" json:"secret_type,omitempty"`
	Name         string                `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
	Metadata     map[string]string     `protobuf:"bytes,4,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Resource) Reset() {
	*x = Resource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_resources_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Resource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Resource) ProtoMessage() {}

func (x *Resource) ProtoReflect() protoreflect.Message {
	mi := &file_resources_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Resource.ProtoReflect.Descriptor instead.
func (*Resource) Descriptor() ([]byte, []int) {
	return file_resources_proto_rawDescGZIP(), []int{0}
}

func (x *Resource) GetResourceType() ResourceType {
	if x != nil {
		return x.ResourceType
	}
	return ResourceType_INVALID
}

func (x *Resource) GetSecretType() analyzerpb.SecretType {
	if x != nil {
		return x.SecretType
	}
	return analyzerpb.SecretType(0)
}

func (x *Resource) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Resource) GetMetadata() map[string]string {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_resources_proto protoreflect.FileDescriptor

var file_resources_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x1a, 0x0e, 0x61, 0x6e,
	0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8f, 0x02, 0x0a,
	0x08, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x3c, 0x0a, 0x0d, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x17, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e, 0x52, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x35, 0x0a, 0x0b, 0x73, 0x65, 0x63, 0x72, 0x65,
	0x74, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x61,
	0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x0a, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x3d, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73,
	0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x1a, 0x3b, 0x0a, 0x0d, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x2a, 0xb5,
	0x01, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12,
	0x0b, 0x0a, 0x07, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07,
	0x50, 0x52, 0x4f, 0x4a, 0x45, 0x43, 0x54, 0x10, 0x01, 0x12, 0x0d, 0x0a, 0x09, 0x57, 0x4f, 0x52,
	0x4b, 0x53, 0x50, 0x41, 0x43, 0x45, 0x10, 0x02, 0x12, 0x0e, 0x0a, 0x0a, 0x52, 0x45, 0x50, 0x4f,
	0x53, 0x49, 0x54, 0x4f, 0x52, 0x59, 0x10, 0x03, 0x12, 0x08, 0x0a, 0x04, 0x55, 0x53, 0x45, 0x52,
	0x10, 0x04, 0x12, 0x08, 0x0a, 0x04, 0x47, 0x49, 0x53, 0x54, 0x10, 0x05, 0x12, 0x10, 0x0a, 0x0c,
	0x4f, 0x52, 0x47, 0x41, 0x4e, 0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x10, 0x06, 0x12, 0x09,
	0x0a, 0x05, 0x4d, 0x4f, 0x44, 0x45, 0x4c, 0x10, 0x07, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x4f, 0x4d,
	0x41, 0x49, 0x4e, 0x10, 0x08, 0x12, 0x09, 0x0a, 0x05, 0x54, 0x41, 0x42, 0x4c, 0x45, 0x10, 0x09,
	0x12, 0x0c, 0x0a, 0x08, 0x45, 0x4e, 0x44, 0x50, 0x4f, 0x49, 0x4e, 0x54, 0x10, 0x0a, 0x12, 0x0c,
	0x0a, 0x08, 0x44, 0x41, 0x54, 0x41, 0x42, 0x41, 0x53, 0x45, 0x10, 0x0b, 0x12, 0x08, 0x0a, 0x04,
	0x53, 0x48, 0x4f, 0x50, 0x10, 0x0c, 0x42, 0x46, 0x5a, 0x44, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x72, 0x75, 0x66, 0x66, 0x6c, 0x65, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x69, 0x74, 0x79, 0x2f, 0x74, 0x72, 0x75, 0x66, 0x66, 0x6c, 0x65, 0x68, 0x6f, 0x67, 0x2f,
	0x76, 0x33, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2f,
	0x70, 0x62, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x70, 0x62, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_resources_proto_rawDescOnce sync.Once
	file_resources_proto_rawDescData = file_resources_proto_rawDesc
)

func file_resources_proto_rawDescGZIP() []byte {
	file_resources_proto_rawDescOnce.Do(func() {
		file_resources_proto_rawDescData = protoimpl.X.CompressGZIP(file_resources_proto_rawDescData)
	})
	return file_resources_proto_rawDescData
}

var file_resources_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_resources_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_resources_proto_goTypes = []interface{}{
	(ResourceType)(0),          // 0: resources.ResourceType
	(*Resource)(nil),           // 1: resources.Resource
	nil,                        // 2: resources.Resource.MetadataEntry
	(analyzerpb.SecretType)(0), // 3: analyzer.SecretType
}
var file_resources_proto_depIdxs = []int32{
	0, // 0: resources.Resource.resource_type:type_name -> resources.ResourceType
	3, // 1: resources.Resource.secret_type:type_name -> analyzer.SecretType
	2, // 2: resources.Resource.metadata:type_name -> resources.Resource.MetadataEntry
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_resources_proto_init() }
func file_resources_proto_init() {
	if File_resources_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_resources_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Resource); i {
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
			RawDescriptor: file_resources_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_resources_proto_goTypes,
		DependencyIndexes: file_resources_proto_depIdxs,
		EnumInfos:         file_resources_proto_enumTypes,
		MessageInfos:      file_resources_proto_msgTypes,
	}.Build()
	File_resources_proto = out.File
	file_resources_proto_rawDesc = nil
	file_resources_proto_goTypes = nil
	file_resources_proto_depIdxs = nil
}

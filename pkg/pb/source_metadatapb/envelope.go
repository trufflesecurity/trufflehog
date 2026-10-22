package source_metadatapb

import (
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// MetaData carries a source's location payload in one of two places: a oneof
// arm declared in source_metadata.proto, or an extension declared by a
// downstream consumer (see the extension range in that file). Payload, Wrap,
// and JSONValue hide which of the two holds it, so callers handle both with a
// single type switch over payload message types. Code that reads m.Data or
// calls GetData directly sees only oneof arms and silently misses extensions.

// metaDataOneof returns the MetaData "data" oneof. It is resolved on use
// because package-level variables initialize before the generated file's init
// registers the descriptor.
func metaDataOneof() protoreflect.OneofDescriptor {
	return (*MetaData)(nil).ProtoReflect().Descriptor().Oneofs().ByName("data")
}

// armsByPayload indexes the MetaData oneof arms by the full name of the message
// each arm holds. It is derived from the descriptor so that adding an arm in
// source_metadata.proto needs no change here.
var armsByPayload = sync.OnceValue(func() map[protoreflect.FullName]protoreflect.FieldDescriptor {
	fields := metaDataOneof().Fields()
	arms := make(map[protoreflect.FullName]protoreflect.FieldDescriptor, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		arms[fd.Message().FullName()] = fd
	}
	return arms
})

// Payload returns the location message m carries, whether it is held in a
// oneof arm or in an extension, or nil if m is nil or empty. A oneof arm takes
// precedence over an extension; Wrap never produces a MetaData holding both.
//
// Extensions resolve to their Go type only if the package declaring them is
// linked into the binary. Otherwise they decode as unknown fields and Payload
// returns nil, so binaries that read downstream metadata must import the
// package that declares the extensions.
func (m *MetaData) Payload() proto.Message {
	if m == nil {
		return nil
	}
	r := m.ProtoReflect()
	if fd := r.WhichOneof(metaDataOneof()); fd != nil {
		return r.Get(fd).Message().Interface()
	}

	// More than one extension is a contract violation, but picking the lowest
	// field number keeps the result deterministic if it happens.
	var (
		payload proto.Message
		lowest  protoreflect.FieldNumber
	)
	r.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.IsExtension() && fd.Message() != nil && (payload == nil || fd.Number() < lowest) {
			payload, lowest = v.Message().Interface(), fd.Number()
		}
		return true
	})
	return payload
}

// Wrap returns a MetaData carrying payload. Payload types that a oneof arm
// holds are placed in that arm, so Wrap(&Git{...}) is identical to
// &MetaData{Data: &MetaData_Git{...}}. Any other payload type must be the
// message type of a registered MetaData extension. Wrap returns nil for a nil
// payload.
//
// Wrap panics if payload is neither, because that is a programming error in
// the source constructing it (typically a missing import of the package that
// declares the extension), in the same way proto.SetExtension panics on a
// mismatched type.
func Wrap(payload proto.Message) *MetaData {
	if payload == nil {
		return nil
	}
	pr := payload.ProtoReflect()
	md := &MetaData{}
	if fd, ok := armsByPayload()[pr.Descriptor().FullName()]; ok {
		md.ProtoReflect().Set(fd, protoreflect.ValueOfMessage(pr))
		return md
	}
	xt := extensionFor(pr.Descriptor().FullName())
	if xt == nil {
		panic(fmt.Sprintf("source_metadatapb.Wrap: %s is neither a MetaData oneof arm nor a registered MetaData extension", pr.Descriptor().FullName()))
	}
	md.ProtoReflect().Set(xt.TypeDescriptor(), protoreflect.ValueOfMessage(pr))
	return md
}

// extensionFor finds the registered MetaData extension whose message type is
// payloadName. The global registry is consulted on each call rather than
// cached, because downstream packages register extensions in their own init
// functions, which may run after this package's.
func extensionFor(payloadName protoreflect.FullName) protoreflect.ExtensionType {
	var found protoreflect.ExtensionType
	protoregistry.GlobalTypes.RangeExtensionsByMessage(metaDataOneof().Parent().FullName(), func(xt protoreflect.ExtensionType) bool {
		if md := xt.TypeDescriptor().Message(); md != nil && md.FullName() == payloadName {
			found = xt
			return false
		}
		return true
	})
	return found
}

// JSONValue returns a value whose encoding/json form is the long-standing
// {"Data":{"<Arm>":{...}}} shape for both oneof arms and extensions.
// Customer-facing payloads rely on that shape, but encoding/json cannot see
// extensions, so a MetaData carrying one would otherwise marshal as
// {"Data":null}. An extension's key is its field name in the same Go
// CamelCase that names oneof wrapper fields, so a payload moved from arm N to
// an extension of the same name keeps its JSON key.
//
// This is deliberately not a MarshalJSON method: structs embed *MetaData
// anonymously, and a promoted MarshalJSON would replace their entire encoding.
func (m *MetaData) JSONValue() any {
	if m == nil || m.Data != nil {
		return m
	}
	var (
		key     string
		payload proto.Message
		lowest  protoreflect.FieldNumber
	)
	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.IsExtension() && fd.Message() != nil && (payload == nil || fd.Number() < lowest) {
			key, payload, lowest = goCamelCase(string(fd.Name())), v.Message().Interface(), fd.Number()
		}
		return true
	})
	if payload == nil {
		return m
	}
	return map[string]map[string]any{"Data": {key: payload}}
}

// goCamelCase converts a proto field name to the Go identifier protoc-gen-go
// gives the matching oneof wrapper field, following the rules of
// google.golang.org/protobuf/internal/strs.GoCamelCase, which is not
// importable. TestGoCamelCaseMatchesOneofWrappers pins it to the generated
// wrapper names.
func goCamelCase(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.' && i+1 < len(s) && isASCIILower(s[i+1]):
			// Skip over '.' in ".{{lowercase}}".
		case c == '.':
			b.WriteByte('_')
		case c == '_' && (i == 0 || s[i-1] == '.'):
			// A leading underscore becomes 'X' so the identifier stays exported.
			b.WriteByte('X')
		case c == '_' && i+1 < len(s) && isASCIILower(s[i+1]):
			// Skip over '_' in "_{{lowercase}}".
		case isASCIIDigit(c):
			b.WriteByte(c)
		default:
			// Capitalize the first letter of each word.
			if isASCIILower(c) {
				c -= 'a' - 'A'
			}
			b.WriteByte(c)
			for ; i+1 < len(s) && isASCIILower(s[i+1]); i++ {
				b.WriteByte(s[i+1])
			}
		}
	}
	return b.String()
}

func isASCIILower(c byte) bool { return 'a' <= c && c <= 'z' }
func isASCIIDigit(c byte) bool { return '0' <= c && c <= '9' }

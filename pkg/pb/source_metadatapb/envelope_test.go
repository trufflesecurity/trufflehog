package source_metadatapb_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb/internal/testextpb"
)

func marshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestWrapArmMatchesLiteral(t *testing.T) {
	git := &source_metadatapb.Git{Commit: "abc", File: "a.go", Line: 7}

	md := source_metadatapb.Wrap(git)

	assert.True(t, proto.Equal(&source_metadatapb.MetaData{Data: &source_metadatapb.MetaData_Git{Git: git}}, md))
	assert.Same(t, git, md.GetGit())
	assert.Same(t, git, md.Payload())
}

func TestWrapExtension(t *testing.T) {
	payload := &testextpb.Downstream{Path: "p", Line: 3}

	md := source_metadatapb.Wrap(payload)

	assert.Nil(t, md.GetData(), "extensions are not oneof arms")
	assert.True(t, proto.HasExtension(md, testextpb.E_DownstreamSource))
	assert.True(t, proto.Equal(payload, md.Payload()))
}

func TestWrapNil(t *testing.T) {
	assert.Nil(t, source_metadatapb.Wrap(nil))
}

func TestWrapPanicsOnUnknownPayloadType(t *testing.T) {
	assert.PanicsWithValue(t,
		"source_metadatapb.Wrap: google.protobuf.Duration is neither a MetaData oneof arm nor a registered MetaData extension",
		func() { source_metadatapb.Wrap(durationpb.New(0)) },
	)
}

func TestPayloadEmpty(t *testing.T) {
	var nilMD *source_metadatapb.MetaData
	assert.Nil(t, nilMD.Payload())
	assert.Nil(t, (&source_metadatapb.MetaData{}).Payload())
}

// Every oneof arm must round-trip through Wrap and Payload, so adding an arm
// to source_metadata.proto needs no change to the envelope helpers.
func TestWrapCoversEveryArm(t *testing.T) {
	fields := (&source_metadatapb.MetaData{}).ProtoReflect().Descriptor().Oneofs().ByName("data").Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		t.Run(string(fd.Name()), func(t *testing.T) {
			mt, err := protoregistry.GlobalTypes.FindMessageByName(fd.Message().FullName())
			require.NoError(t, err)
			payload := mt.New().Interface()

			md := source_metadatapb.Wrap(payload)

			assert.Equal(t, fd, md.ProtoReflect().WhichOneof(fd.ContainingOneof()))
			assert.Same(t, payload, md.Payload())
		})
	}
}

// An extension is encoded exactly like a oneof arm holding the same message at
// the same field number. This is what lets a source's metadata move between
// an arm and an extension without a wire change.
func TestExtensionWireEncodingMatchesArmEncoding(t *testing.T) {
	payload := &testextpb.Downstream{Path: "p", Link: "l", Line: 3}

	want := protowire.AppendTag(nil, 1000, protowire.BytesType)
	want = protowire.AppendBytes(want, marshal(t, payload))

	assert.Equal(t, want, marshal(t, source_metadatapb.Wrap(payload)))
	assert.Equal(t, want, marshal(t, &testextpb.LegacyMetaData{
		Data: &testextpb.LegacyMetaData_DownstreamSource{DownstreamSource: payload},
	}))
}

// Readers on either side of an arm-to-extension move decode each other: bytes
// written with the arm decode as the extension, and vice versa.
func TestArmMovedToExtensionInteroperates(t *testing.T) {
	payload := &testextpb.Downstream{Path: "p", Link: "l", Line: 3}
	legacy := &testextpb.LegacyMetaData{Data: &testextpb.LegacyMetaData_DownstreamSource{DownstreamSource: payload}}

	var md source_metadatapb.MetaData
	require.NoError(t, proto.Unmarshal(marshal(t, legacy), &md))
	assert.True(t, proto.Equal(payload, md.Payload()))

	var back testextpb.LegacyMetaData
	require.NoError(t, proto.Unmarshal(marshal(t, source_metadatapb.Wrap(payload)), &back))
	assert.True(t, proto.Equal(payload, back.GetDownstreamSource()))
}

// The engine clones chunk metadata before annotating results and dedupes
// results on the %+v rendering of their metadata. Extensions must survive the
// clone and keep distinct locations distinct in that key.
func TestExtensionSurvivesCloneAndDedupeKey(t *testing.T) {
	a := source_metadatapb.Wrap(&testextpb.Downstream{Path: "p", Line: 1})
	b := source_metadatapb.Wrap(&testextpb.Downstream{Path: "p", Line: 2})

	assert.True(t, proto.Equal(a, proto.Clone(a)))
	assert.NotEqual(t, fmt.Sprintf("%+v", a), fmt.Sprintf("%+v", b))
}

func TestJSONValueArmMatchesDefaultEncoding(t *testing.T) {
	md := source_metadatapb.Wrap(&source_metadatapb.Github{Repository: "r", Line: 4})

	got, err := json.Marshal(md.JSONValue())
	require.NoError(t, err)
	want, err := json.Marshal(md)
	require.NoError(t, err)

	assert.JSONEq(t, `{"Data":{"Github":{"repository":"r","line":4}}}`, string(want))
	assert.Equal(t, string(want), string(got))
}

// A payload carried as an extension renders with the same JSON key it had as
// a oneof arm, so customer-facing payloads do not change when it moves.
func TestJSONValueExtensionMatchesLegacyArm(t *testing.T) {
	payload := &testextpb.Downstream{Path: "p", Line: 3}
	legacy := &testextpb.LegacyMetaData{Data: &testextpb.LegacyMetaData_DownstreamSource{DownstreamSource: payload}}

	got, err := json.Marshal(source_metadatapb.Wrap(payload).JSONValue())
	require.NoError(t, err)
	want, err := json.Marshal(legacy)
	require.NoError(t, err)

	assert.JSONEq(t, `{"Data":{"DownstreamSource":{"path":"p","line":3}}}`, string(want))
	assert.Equal(t, string(want), string(got))
}

func TestJSONValueEmpty(t *testing.T) {
	var nilMD *source_metadatapb.MetaData
	got, err := json.Marshal(nilMD.JSONValue())
	require.NoError(t, err)
	assert.Equal(t, "null", string(got))

	got, err = json.Marshal((&source_metadatapb.MetaData{}).JSONValue())
	require.NoError(t, err)
	assert.Equal(t, `{"Data":null}`, string(got))
}

// Output structs embed *MetaData anonymously. A MarshalJSON method on MetaData
// would be promoted to them and replace their whole encoding.
func TestMetaDataDoesNotImplementJSONMarshaler(t *testing.T) {
	_, ok := any(&source_metadatapb.MetaData{}).(json.Marshaler)
	assert.False(t, ok)
}

func TestGoCamelCaseMatchesOneofWrappers(t *testing.T) {
	fields := (&source_metadatapb.MetaData{}).ProtoReflect().Descriptor().Oneofs().ByName("data").Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		mt, err := protoregistry.GlobalTypes.FindMessageByName(fd.Message().FullName())
		require.NoError(t, err)
		wrapper := reflect.TypeOf(source_metadatapb.Wrap(mt.New().Interface()).Data).Elem()

		assert.Equal(t, wrapper.Field(0).Name, source_metadatapb.GoCamelCase(string(fd.Name())), "arm %s", fd.Name())
	}
}

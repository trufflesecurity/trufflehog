package form

import (
	"reflect"
	"testing"
)

func TestBuildArgsEmitModes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		specs  []FieldSpec
		values map[string]string
		want   []string
	}{
		{
			name:   "empty spec set emits nothing",
			specs:  nil,
			values: nil,
			want:   nil,
		},
		{
			name: "long flag with space-containing value",
			specs: []FieldSpec{
				{Key: "path", Emit: EmitLongFlag},
			},
			values: map[string]string{"path": "/tmp/my folder"},
			want:   []string{"--path", "/tmp/my folder"},
		},
		{
			name: "long flag eq with value",
			specs: []FieldSpec{
				{Key: "results", Emit: EmitLongFlagEq},
			},
			values: map[string]string{"results": "verified"},
			want:   []string{"--results=verified"},
		},
		{
			name: "long flag and long flag eq skip empty values",
			specs: []FieldSpec{
				{Key: "a", Emit: EmitLongFlag},
				{Key: "b", Emit: EmitLongFlagEq},
			},
			values: map[string]string{"a": "", "b": "  "},
			want:   nil,
		},
		{
			name: "presence only emits when truthy",
			specs: []FieldSpec{
				{Key: "json", Emit: EmitPresence},
				{Key: "no-verification", Emit: EmitPresence},
				{Key: "verbose", Emit: EmitPresence},
			},
			values: map[string]string{
				"json":            "true",
				"no-verification": "false",
				"verbose":         "",
			},
			want: []string{"--json"},
		},
		{
			name: "constant expands when truthy",
			specs: []FieldSpec{
				{Key: "only-verified", Emit: EmitConstant, Constant: []string{"--results=verified"}},
			},
			values: map[string]string{"only-verified": "true"},
			want:   []string{"--results=verified"},
		},
		{
			name: "constant emits nothing when falsy",
			specs: []FieldSpec{
				{Key: "only-verified", Emit: EmitConstant, Constant: []string{"--results=verified"}},
			},
			values: map[string]string{"only-verified": ""},
			want:   nil,
		},
		{
			name: "positional renders value only",
			specs: []FieldSpec{
				{Key: "uri", Emit: EmitPositional},
			},
			values: map[string]string{"uri": "https://example.com/repo.git"},
			want:   []string{"https://example.com/repo.git"},
		},
		{
			name: "emit none contributes nothing",
			specs: []FieldSpec{
				{Key: "gate", Emit: EmitNone},
				{Key: "real", Emit: EmitLongFlag},
			},
			values: map[string]string{"gate": "true", "real": "value"},
			want:   []string{"--real", "value"},
		},
		{
			name: "ordering follows spec order",
			specs: []FieldSpec{
				{Key: "a", Emit: EmitLongFlag},
				{Key: "b", Emit: EmitPresence},
				{Key: "c", Emit: EmitPositional},
			},
			values: map[string]string{"a": "1", "b": "true", "c": "pos"},
			want:   []string{"--a", "1", "--b", "pos"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := BuildArgs(tc.specs, tc.values)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("BuildArgs(%v) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

func TestRequired(t *testing.T) {
	t.Parallel()
	r := Required()
	if err := r(""); err == nil {
		t.Fatal("Required must reject empty")
	}
	if err := r("   "); err == nil {
		t.Fatal("Required must reject whitespace-only")
	}
	if err := r("ok"); err != nil {
		t.Fatalf("Required must accept non-empty: %v", err)
	}
}

func TestInteger(t *testing.T) {
	t.Parallel()
	v := Integer(1, 10)
	if err := v(""); err != nil {
		t.Fatalf("Integer must accept empty (pair with Required): %v", err)
	}
	if err := v("abc"); err == nil {
		t.Fatal("Integer must reject non-integer")
	}
	if err := v("0"); err == nil {
		t.Fatal("Integer must reject below min")
	}
	if err := v("11"); err == nil {
		t.Fatal("Integer must reject above max")
	}
	if err := v("5"); err != nil {
		t.Fatalf("Integer must accept in range: %v", err)
	}
}

func TestOneOf(t *testing.T) {
	t.Parallel()
	v := OneOf("verified", "unverified")
	if err := v("verified"); err != nil {
		t.Fatalf("OneOf must accept match: %v", err)
	}
	if err := v("nonsense"); err == nil {
		t.Fatal("OneOf must reject non-match")
	}
	if err := v(""); err != nil {
		t.Fatalf("OneOf must accept empty (pair with Required): %v", err)
	}
}

func TestXOrGroupGitHubFixture(t *testing.T) {
	t.Parallel()
	specs := []FieldSpec{
		{Key: "org", Group: "target"},
		{Key: "repo", Group: "target"},
		{Key: "endpoint"}, // not in group
	}
	c := XOrGroup("target", 1, 1, specs)

	if err := c(map[string]string{"org": "truffle", "repo": ""}); err != nil {
		t.Fatalf("exactly-one satisfied: %v", err)
	}
	if err := c(map[string]string{"org": "", "repo": "secrets"}); err != nil {
		t.Fatalf("exactly-one satisfied: %v", err)
	}
	if err := c(map[string]string{"org": "", "repo": ""}); err == nil {
		t.Fatal("must reject when none set")
	}
	if err := c(map[string]string{"org": "a", "repo": "b"}); err == nil {
		t.Fatal("must reject when both set")
	}
	if err := c(map[string]string{"org": "   ", "repo": ""}); err == nil {
		t.Fatal("whitespace must not count as set")
	}
}

func TestFormArgsIntegration(t *testing.T) {
	t.Parallel()
	specs := []FieldSpec{
		{Key: "repo", Label: "Repo", Kind: KindText, Emit: EmitLongFlag},
		{Key: "json", Label: "JSON", Kind: KindCheckbox, Emit: EmitPresence},
		{Key: "results", Kind: KindSelect, Emit: EmitLongFlagEq, Options: []SelectOption{
			{Label: "All", Value: "all"},
			{Label: "Verified", Value: "verified"},
		}, Default: "verified"},
	}
	f := New(specs)

	f.Fields()[0].SetValue("/tmp/my repo")
	f.Fields()[1].SetValue("true")

	got := f.Args()
	want := []string{"--repo", "/tmp/my repo", "--json", "--results=verified"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Form.Args() = %v, want %v", got, want)
	}
}

func TestFormValidBlocksOnMissingRequired(t *testing.T) {
	t.Parallel()
	specs := []FieldSpec{
		{Key: "key", Kind: KindText, Validators: []Validate{Required()}},
	}
	f := New(specs)
	if f.Valid() {
		t.Fatal("empty required must not validate")
	}
	f.Fields()[0].SetValue("ok")
	if !f.Valid() {
		t.Fatal("non-empty required must validate")
	}
}

func TestFormValidRunsConstraints(t *testing.T) {
	t.Parallel()
	specs := []FieldSpec{
		{Key: "org", Group: "target"},
		{Key: "repo", Group: "target"},
	}
	f := New(specs, XOrGroup("target", 1, 1, specs))
	if f.Valid() {
		t.Fatal("neither field set must fail constraint")
	}
	f.Fields()[0].SetValue("truffle")
	if !f.Valid() {
		t.Fatal("org set only must pass")
	}
	f.Fields()[1].SetValue("secrets")
	if f.Valid() {
		t.Fatal("both set must fail constraint")
	}
}

package decoders

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestUnicodeEscape_FromChunk(t *testing.T) {
	tests := []struct {
		name    string
		chunk   *sources.Chunk
		want    *sources.Chunk
		wantErr bool
	}{
		// U+1234
		{
			name: "[notation] all escaped",
			chunk: &sources.Chunk{
				Data: []byte("U+0074 U+006f U+006b U+0065 U+006e U+003a U+0020 U+0022 U+0067 U+0068 U+0070 U+005f U+0049 U+0077 U+0064 U+004d U+0078 U+0039 U+0057 U+0046 U+0057 U+0052 U+0052 U+0066 U+004d U+0068 U+0054 U+0059 U+0069 U+0061 U+0056 U+006a U+005a U+0037 U+0038 U+004a U+0066 U+0075 U+0061 U+006d U+0076 U+006e U+0030 U+0059 U+0057 U+0052 U+004d U+0030 U+0022"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},
		// \u1234
		{
			name: "[slash] all escaped",
			chunk: &sources.Chunk{
				Data: []byte("\\u0074\\u006f\\u006b\\u0065\\u006e\\u003a\\u0020\\u0022\\u0067\\u0068\\u0070\\u005f\\u0049\\u0077\\u0064\\u004d\\u0078\\u0039\\u0057\\u0046\\u0057\\u0052\\u0052\\u0066\\u004d\\u0068\\u0054\\u0059\\u0069\\u0061\\u0056\\u006a\\u005a\\u0037\\u0038\\u004a\\u0066\\u0075\\u0061\\u006d\\u0076\\u006e\\u0030\\u0059\\u0057\\u0052\\u004d\\u0030\\u0022"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},
		{
			name: "[slash] mixed content",
			chunk: &sources.Chunk{
				Data: []byte("npm config set @trufflesec:registry=https://npm.pkg.github.com\nnpm config set //npm.pkg.github.com:_authToken=$'\\u0067hp_9ovSHEBCq0drG42yjoam76iNybtqLN25CgSf'"),
			},
			want: &sources.Chunk{
				Data: []byte("npm config set @trufflesec:registry=https://npm.pkg.github.com\nnpm config set //npm.pkg.github.com:_authToken=$'ghp_9ovSHEBCq0drG42yjoam76iNybtqLN25CgSf'"),
			},
		},
		{
			name: "[slash] multiple slashes",
			chunk: &sources.Chunk{
				Data: []byte(`SameValue("hello","\\u0068el\\u006co");          // true`),
			},
			want: &sources.Chunk{
				Data: []byte(`SameValue("hello","hello");          // true`),
			},
		},

		// New test cases for additional Unicode escape formats

		// \u{X} format - Rust, Swift, some JS, etc.
		{
			name: "[brace] \\u{X} format - Rust/Swift style",
			chunk: &sources.Chunk{
				Data: []byte("\\u{74}\\u{6f}\\u{6b}\\u{65}\\u{6e}\\u{3a}\\u{20}\\u{22}\\u{67}\\u{68}\\u{70}\\u{5f}\\u{49}\\u{77}\\u{64}\\u{4d}\\u{78}\\u{39}\\u{57}\\u{46}\\u{57}\\u{52}\\u{52}\\u{66}\\u{4d}\\u{68}\\u{54}\\u{59}\\u{69}\\u{61}\\u{56}\\u{6a}\\u{5a}\\u{37}\\u{38}\\u{4a}\\u{66}\\u{75}\\u{61}\\u{6d}\\u{76}\\u{6e}\\u{30}\\u{59}\\u{57}\\u{52}\\u{4d}\\u{30}\\u{22}"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},

		// \U00XXXXXX format - Python, etc.
		{
			name: "[long] \\U00XXXXXX format - Python style",
			chunk: &sources.Chunk{
				Data: []byte("\\U00000074\\U0000006f\\U0000006b\\U00000065\\U0000006e\\U0000003a\\U00000020\\U00000022\\U00000067\\U00000068\\U00000070\\U0000005f\\U00000049\\U00000077\\U00000064\\U0000004d\\U00000078\\U00000039\\U00000057\\U00000046\\U00000057\\U00000052\\U00000052\\U00000066\\U0000004d\\U00000068\\U00000054\\U00000059\\U00000069\\U00000061\\U00000056\\U0000006a\\U0000005a\\U00000037\\U00000038\\U0000004a\\U00000066\\U00000075\\U00000061\\U0000006d\\U00000076\\U0000006e\\U00000030\\U00000059\\U00000057\\U00000052\\U0000004d\\U00000030\\U00000022"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},

		// \x{X} format - Perl
		{
			name: "[perl] \\x{X} format - Perl style",
			chunk: &sources.Chunk{
				Data: []byte("\\x{74}\\x{6f}\\x{6b}\\x{65}\\x{6e}\\x{3a}\\x{20}\\x{22}\\x{67}\\x{68}\\x{70}\\x{5f}\\x{49}\\x{77}\\x{64}\\x{4d}\\x{78}\\x{39}\\x{57}\\x{46}\\x{57}\\x{52}\\x{52}\\x{66}\\x{4d}\\x{68}\\x{54}\\x{59}\\x{69}\\x{61}\\x{56}\\x{6a}\\x{5a}\\x{37}\\x{38}\\x{4a}\\x{66}\\x{75}\\x{61}\\x{6d}\\x{76}\\x{6e}\\x{30}\\x{59}\\x{57}\\x{52}\\x{4d}\\x{30}\\x{22}"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},

		// \X format - CSS (space delimited)
		// ToDo: Look into supporting CSS where there is no whitespace ex: \013322\013171\013001. Currently not supported by this implementation.
		{
			name: "[css] \\X format - CSS style",
			chunk: &sources.Chunk{
				Data: []byte("\\74 \\6f \\6b \\65 \\6e \\3a \\20 \\22 \\67 \\68 \\70 \\5f \\49 \\77 \\64 \\4d \\78 \\39 \\57 \\46 \\57 \\52 \\52 \\66 \\4d \\68 \\54 \\59 \\69 \\61 \\56 \\6a \\5a \\37 \\38 \\4a \\66 \\75 \\61 \\6d \\76 \\6e \\30 \\59 \\57 \\52 \\4d \\30 \\22 "),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},

		// &#xX; format - HTML/XML
		{
			name: "[html] &#xX; format - HTML/XML style",
			chunk: &sources.Chunk{
				Data: []byte("&#x74;&#x6f;&#x6b;&#x65;&#x6e;&#x3a;&#x20;&#x22;&#x67;&#x68;&#x70;&#x5f;&#x49;&#x77;&#x64;&#x4d;&#x78;&#x39;&#x57;&#x46;&#x57;&#x52;&#x52;&#x66;&#x4d;&#x68;&#x54;&#x59;&#x69;&#x61;&#x56;&#x6a;&#x5a;&#x37;&#x38;&#x4a;&#x66;&#x75;&#x61;&#x6d;&#x76;&#x6e;&#x30;&#x59;&#x57;&#x52;&#x4d;&#x30;&#x22;"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},

		// %uXXXX format - Percent-encoding (non-standard)
		{
			name: "[percent] %uXXXX format - Percent encoding",
			chunk: &sources.Chunk{
				Data: []byte("%u0074%u006f%u006b%u0065%u006e%u003a%u0020%u0022%u0067%u0068%u0070%u005f%u0049%u0077%u0064%u004d%u0078%u0039%u0057%u0046%u0057%u0052%u0052%u0066%u004d%u0068%u0054%u0059%u0069%u0061%u0056%u006a%u005a%u0037%u0038%u004a%u0066%u0075%u0061%u006d%u0076%u006e%u0030%u0059%u0057%u0052%u004d%u0030%u0022"),
			},
			want: &sources.Chunk{
				Data: []byte("token: \"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\""),
			},
		},

		// // 0xX format - Hexadecimal notation with space separation
		// {
		// 	name: "[hex] 0xX format - Hex with spaces",
		// 	chunk: &sources.Chunk{
		// 		Data: []byte("0x74 0x6f 0x6b 0x65 0x6e 0x3a 0x20 0x22 0x67 0x68 0x70 0x5f 0x49 0x77 0x64 0x4d 0x78 0x39 0x57 0x46 0x57 0x52 0x52 0x66 0x4d 0x68 0x54 0x59 0x69 0x61 0x56 0x6a 0x5a 0x37 0x38 0x4a 0x66 0x75 0x61 0x6d 0x76 0x6e 0x30 0x59 0x57 0x52 0x4d 0x30 0x22 "),
		// 	},
		// 	want: &sources.Chunk{
		// 		Data: []byte("token: \"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\""),
		// 	},
		// },

		// // 0xX format - Hexadecimal notation with comma separation
		// {
		// 	name: "[hex] 0xX format - Hex with commas",
		// 	chunk: &sources.Chunk{
		// 		Data: []byte("0x74,0x6f,0x6b,0x65,0x6e,0x3a,0x20,0x22,0x67,0x68,0x70,0x5f,0x49,0x77,0x64,0x4d,0x78,0x39,0x57,0x46,0x57,0x52,0x52,0x66,0x4d,0x68,0x54,0x59,0x69,0x61,0x56,0x6a,0x5a,0x37,0x38,0x4a,0x66,0x75,0x61,0x6d,0x76,0x6e,0x30,0x59,0x57,0x52,0x4d,0x30,0x22"),
		// 	},
		// 	want: &sources.Chunk{
		// 		Data: []byte("token: \"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\""),
		// 	},
		// },

		// Test cases for mixed content with new formats
		{
			name: "[mixed] \\u{X} in code context",
			chunk: &sources.Chunk{
				Data: []byte("const secret = \"\\u{41}\\u{4b}\\u{49}\\u{41}\\u{55}\\u{4d}\\u{34}\\u{47}\\u{36}\\u{4f}\\u{36}\\u{4e}\\u{41}\\u{4b}\\u{45}\\u{37}\\u{4c}\\u{43}\\u{44}\\u{4a}\";"),
			},
			want: &sources.Chunk{
				Data: []byte("const secret = \"AKIAUM4G6O6NAKE7LCDJ\";"),
			},
		},

		{
			name: "[mixed] HTML entity in web context",
			chunk: &sources.Chunk{
				Data: []byte("<span>AWS Key: &#x41;&#x4b;&#x49;&#x41;&#x55;&#x4d;&#x34;&#x47;&#x36;&#x4f;&#x36;&#x4e;&#x41;&#x4b;&#x45;&#x37;&#x4c;&#x43;&#x44;&#x4a;</span>"),
			},
			want: &sources.Chunk{
				Data: []byte("<span>AWS Key: AKIAUM4G6O6NAKE7LCDJ</span>"),
			},
		},

		// Test cases for higher Unicode values (non-BMP)
		{
			name: "[emoji] \\u{X} with emoji",
			chunk: &sources.Chunk{
				Data: []byte("\\u{1f600} Happy face emoji"),
			},
			want: &sources.Chunk{
				Data: []byte("😀 Happy face emoji"),
			},
		},

		{
			name: "[emoji] \\U00XXXXXX with emoji",
			chunk: &sources.Chunk{
				Data: []byte("\\U0001f600 Happy face emoji"),
			},
			want: &sources.Chunk{
				Data: []byte("😀 Happy face emoji"),
			},
		},

		// nothing
		{
			name: "no escaped",
			chunk: &sources.Chunk{
				Data: []byte(`-//npm.fontawesome.com/:_authToken=12345678-2323-1111-1111-12345670B312
+//npm.fontawesome.com/:_authToken=REMOVED_TOKEN`),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &EscapedUnicode{}
			got := d.FromChunk(tt.chunk)
			if tt.want != nil {
				if got == nil {
					t.Fatal("got nil, did not want nil")
				}
				if diff := pretty.Compare(string(tt.want.Data), string(got.Data)); diff != "" {
					t.Errorf("UnicodeEscape.FromChunk() %s diff: (-want +got)\n%s", tt.name, diff)
				}
			} else {
				if got != nil {
					t.Error("Expected nil chunk")
				}
			}
		})
	}
}

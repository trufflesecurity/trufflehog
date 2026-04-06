package decoders

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestHTML_Type(t *testing.T) {
	d := &HTML{}
	if got := d.Type(); got != detectorspb.DecoderType_HTML {
		t.Errorf("Type() = %v, want %v", got, detectorspb.DecoderType_HTML)
	}
}

// TestHTML_FromChunk verifies the HTML decoder extracts secrets from HTML content
// that sources like MS Teams and Confluence emit. The test cases are grouped by
// the category of extraction they exercise:
//
//   - Guard clauses: nil, empty, and non-HTML input return nil.
//   - Text node extraction: secrets split across inline tags are rejoined;
//     HTML entities (&amp;) are decoded by the parser.
//   - Attribute value extraction: high-signal attrs (href, src, data-*, value,
//     content, alt, title, action) are emitted; URL percent-encoding is decoded;
//     empty/anchor-only hrefs are skipped.
//   - Script / style / comment content: all included because they frequently
//     contain embedded credentials.
//   - Code and pre blocks: preserved verbatim (common secret location).
//   - Whitespace and token boundaries: block elements (p, div, br, tr, td, li)
//     insert newlines; inline elements preserve text continuity to avoid
//     accidental token joins.
//   - Real-world formats: Confluence storage-format HTML and Teams message HTML
//     with secrets in typical positions.
//   - Integration: a mixed-content case exercises text nodes, URL-decoded attrs,
//     script content, and HTML comments in a single chunk.
func TestHTML_FromChunk(t *testing.T) {
	tests := []struct {
		name    string
		chunk   *sources.Chunk
		want    string
		wantNil bool
	}{
		// --- Guard clauses: decoder returns nil for non-applicable input ---
		{
			name:    "nil chunk",
			chunk:   nil,
			wantNil: true,
		},
		{
			name:    "empty data",
			chunk:   &sources.Chunk{Data: []byte{}},
			wantNil: true,
		},
		{
			name:    "plain text (no HTML)",
			chunk:   &sources.Chunk{Data: []byte("just some plain text with no tags")},
			wantNil: true,
		},

		// --- Text node extraction ---
		{
			// Core scenario: a secret is split across formatting tags by the
			// rich-text editor. The parser concatenates adjacent text nodes.
			name:  "secret split across span tags",
			chunk: &sources.Chunk{Data: []byte(`<p><span>AKIA</span><span>1234567890ABCDEF</span></p>`)},
			want:  "AKIA1234567890ABCDEF",
		},
		{
			// Confluence/Teams encode '&' as '&amp;'. The HTML parser
			// automatically unescapes entities so detector regexes can match.
			name:  "HTML entities decoded",
			chunk: &sources.Chunk{Data: []byte(`<p>key=abc&amp;secret=hunter2</p>`)},
			want:  "key=abc&secret=hunter2",
		},

		// --- Attribute value extraction ---
		{
			// Secrets in href URLs (e.g. tokens in query params).
			name:  "attribute value extraction - href",
			chunk: &sources.Chunk{Data: []byte(`<a href="https://api.example.com?token=sk-live-1234">link</a>`)},
			want:  "https://api.example.com?token=sk-live-1234\nlink",
		},
		{
			// Secrets in src URLs (e.g. image CDN tokens).
			name:  "attribute value extraction - src",
			chunk: &sources.Chunk{Data: []byte(`<img src="https://cdn.example.com/img?key=secret123"/>`)},
			want:  "https://cdn.example.com/img?key=secret123",
		},
		{
			// Percent-encoded characters in attribute values (%2D -> '-',
			// %5F -> '_') are decoded so detectors see the actual secret.
			name:  "URL-encoded attribute values decoded",
			chunk: &sources.Chunk{Data: []byte(`<a href="https://api.example.com?token=sk%2Dlive%5F1234">docs</a>`)},
			want:  "https://api.example.com?token=sk-live_1234\ndocs",
		},
		{
			// data-* attributes are often used for JS-consumed config values.
			name:  "data-* attributes extracted",
			chunk: &sources.Chunk{Data: []byte(`<div data-api-key="ghp_abc123def456">content</div>`)},
			want:  "ghp_abc123def456\ncontent",
		},
		{
			// src, alt, and title on a single element all extracted.
			name:  "multiple high-signal attributes on one element",
			chunk: &sources.Chunk{Data: []byte(`<img src="https://api.com/img?key=k1" alt="secret: abc123" title="token: def456"/>`)},
			want:  "https://api.com/img?key=k1\nsecret: abc123\ntoken: def456",
		},
		{
			// Anchors with href="#" carry no signal and are skipped.
			name:  "empty href skipped",
			chunk: &sources.Chunk{Data: []byte(`<a href="#">click</a>`)},
			want:  "click",
		},
		{
			// Hidden inputs often carry CSRF tokens or API keys.
			name:  "value attribute on input",
			chunk: &sources.Chunk{Data: []byte(`<input type="hidden" value="sk_test_EXAMPLEKEYEXAMPLEKEYEX"/>`)},
			want:  "sk_test_EXAMPLEKEYEXAMPLEKEYEX",
		},
		{
			// <meta> content attributes may carry API keys for client-side SDKs.
			name:  "meta content attribute",
			chunk: &sources.Chunk{Data: []byte(`<meta name="api-key" content="pk_live_abcdefghij1234567890"/>`)},
			want:  "pk_live_abcdefghij1234567890",
		},
		{
			// Form action URLs can embed secrets in query strings.
			name:  "action attribute on form",
			chunk: &sources.Chunk{Data: []byte(`<form action="https://api.stripe.com/v1/charges?key=sk_live_123"><button>Pay</button></form>`)},
			want:  "https://api.stripe.com/v1/charges?key=sk_live_123\nPay",
		},

		{
			// '+' is a literal character in attribute values (not a space).
			// PathUnescape preserves it while still decoding %XX sequences.
			name:  "plus sign preserved in attribute value",
			chunk: &sources.Chunk{Data: []byte(`<input type="hidden" value="sk_test_abc+def/123"/>`)},
			want:  "sk_test_abc+def/123",
		},

		// --- Script / style / comment content ---
		{
			// Inline <script> blocks frequently contain API keys, tokens,
			// and configuration objects with secrets.
			name:  "script content included",
			chunk: &sources.Chunk{Data: []byte(`<p>hello</p><script>var secret = "ghp_abc123def456";</script>`)},
			want:  "hello\nvar secret = \"ghp_abc123def456\";",
		},
		{
			// CSS can contain secrets in background-image URLs, @import, etc.
			name:  "style content included",
			chunk: &sources.Chunk{Data: []byte(`<p>text</p><style>body { background: url("https://cdn.com?key=secret"); }</style>`)},
			want:  "text\nbody { background: url(\"https://cdn.com?key=secret\"); }",
		},
		{
			// Script following an inline element must NOT concatenate with
			// the preceding text; it needs its own newline boundary.
			name:  "script adjacent to inline text gets boundary",
			chunk: &sources.Chunk{Data: []byte(`<span>text</span><script>var key="secret";</script>`)},
			want:  "text\nvar key=\"secret\";",
		},
		{
			// Style following an inline element must NOT concatenate.
			name:  "style adjacent to inline text gets boundary",
			chunk: &sources.Chunk{Data: []byte(`<span>text</span><style>.x { color: red; }</style>`)},
			want:  "text\n.x { color: red; }",
		},
		{
			// Entity-like sequences in script content are raw text and must
			// NOT be decoded by the residual entity replacer.
			name:  "entities in script preserved as raw text",
			chunk: &sources.Chunk{Data: []byte(`<script>var url = "a=1&amp;b=2";</script>`)},
			want:  `var url = "a=1&amp;b=2";`,
		},
		{
			// Entity-like sequences in style content are raw text.
			name:  "entities in style preserved as raw text",
			chunk: &sources.Chunk{Data: []byte(`<style>body::after { content: "&amp;copy"; }</style>`)},
			want:  `body::after { content: "&amp;copy"; }`,
		},
		{
			// HTML comments are a common place for debug credentials and
			// TODO notes with hardcoded passwords.
			name:  "HTML comment content included",
			chunk: &sources.Chunk{Data: []byte(`<p>visible</p><!-- TODO: remove hardcoded password=hunter2 -->`)},
			want:  "visible\nTODO: remove hardcoded password=hunter2",
		},

		// --- Code and pre blocks ---
		{
			// <pre>/<code> content is preserved verbatim; these blocks are a
			// top location for pasted credentials and key exports.
			name:  "code/pre blocks preserved",
			chunk: &sources.Chunk{Data: []byte(`<pre><code>export AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</code></pre>`)},
			want:  "export AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{
			// Multi-line PEM private keys in <pre> blocks with <br> line breaks
			// are reconstructed with proper newlines for detector matching.
			name:  "private key in pre block",
			chunk: &sources.Chunk{Data: []byte(`<pre>-----BEGIN RSA PRIVATE KEY-----<br>MIIEpAIBAAKCAQEA04up8h<br>-----END RSA PRIVATE KEY-----</pre>`)},
			want:  "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA04up8h\n-----END RSA PRIVATE KEY-----",
		},

		// --- Whitespace and token boundaries ---
		{
			// Block elements (<p>) produce newline boundaries so adjacent
			// paragraphs don't merge tokens.
			name: "block elements produce newlines",
			chunk: &sources.Chunk{Data: []byte(`<div><p>first</p><p>second</p></div>`)},
			want:  "first\nsecond",
		},
		{
			// All <br> variants produce newlines.
			name:  "br tags produce newlines",
			chunk: &sources.Chunk{Data: []byte(`<p>line1<br>line2<br/>line3</p>`)},
			want:  "line1\nline2\nline3",
		},
		{
			// Nested inline elements (<em>, <strong>) do not break the token;
			// text flows continuously so "token=sk-live-abc123" stays intact.
			name:  "nested inline elements preserve text continuity",
			chunk: &sources.Chunk{Data: []byte(`<p>token=<em><strong>sk-live-abc123</strong></em></p>`)},
			want:  "token=sk-live-abc123",
		},
		{
			// <td> elements are block-level: each cell gets its own line,
			// keeping key/value pairs from merging.
			name: "table with secrets",
			chunk: &sources.Chunk{Data: []byte(
				`<table><tr><td>API Key</td><td>AKIAIOSFODNN7EXAMPLE</td></tr>` +
					`<tr><td>Secret</td><td>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr></table>`,
			)},
			want: "API Key\nAKIAIOSFODNN7EXAMPLE\nSecret\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{
			// Even without <tr> wrappers, <td> still inserts block boundaries.
			name: "td cells without enclosing tr still get block boundaries",
			chunk: &sources.Chunk{Data: []byte(
				`<table><td>key</td><td>value</td></table>`,
			)},
			want: "key\nvalue",
		},
		{
			// <li> elements produce separate lines.
			name: "list items produce separate lines",
			chunk: &sources.Chunk{Data: []byte(
				`<ul><li>token: abc123</li><li>secret: def456</li></ul>`,
			)},
			want: "token: abc123\nsecret: def456",
		},

		// --- Real-world source formats ---
		{
			// Confluence storage format: secrets split across <strong> tags,
			// an AWS key in plain text, and an href with a URL. Exercises text
			// node concatenation, attribute extraction, and block boundaries
			// together.
			name: "confluence storage format - real world",
			chunk: &sources.Chunk{Data: []byte(
				`<p>Our API credentials:</p>` +
					`<p>Key: <strong>AKIA</strong><strong>IOSFODNN7EXAMPLE</strong></p>` +
					`<p>Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</p>` +
					`<p>See <a href="https://console.aws.amazon.com">AWS Console</a></p>`,
			)},
			want: "Our API credentials:\nKey: AKIAIOSFODNN7EXAMPLE\nSecret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nSee\nhttps://console.aws.amazon.com\nAWS Console",
		},
		{
			// Teams message HTML: nested <div> wrappers around <p> tags
			// containing a GitHub PAT. Verifies that redundant block wrappers
			// collapse to clean newlines.
			name: "teams message HTML - real world",
			chunk: &sources.Chunk{Data: []byte(
				`<div><div>` +
					`<p>Here is the token for the staging env:</p>` +
					`<p>ghp_ABCDEFghijklmnop1234567890abcde</p>` +
					`</div></div>`,
			)},
			want: "Here is the token for the staging env:\nghp_ABCDEFghijklmnop1234567890abcde",
		},

		// --- Syntax highlight boundary detection ---
		{
			// Teams renders code blocks as adjacent <span> elements within a
			// single <p>, using highlight.js classes for syntax coloring.
			// Newlines from the original code are lost. The decoder detects
			// hljs-* classes and inserts newlines at those boundaries while
			// still concatenating non-hljs sibling spans (preserving
			// mid-token color splits like the value below split across 3 spans).
			name: "teams code block with hljs syntax highlighting",
			chunk: &sources.Chunk{Data: []byte(
				`<p>` +
					`<span style="color:#1E53A3"><strong>[header]</strong></span>` +
					`<span class="hljs-function" style="color:#1E53A3">key_one</span>` +
					`<span> = FIRST_VALUE_ABCDEFGH</span>` +
					`<span class="hljs-function" style="color:#1E53A3">key_two</span>` +
					`<span> = SECOND_VAL_PART_</span>` +
					`<span style="color:#1E53A3">X</span>` +
					`<span>_END_OF_VALUE</span>` +
					`<span class="hljs-function" style="color:#1E53A3">format</span>` +
					`<span> = json</span>` +
					`</p>`,
			)},
			want: "[header]\nkey_one = FIRST_VALUE_ABCDEFGH\nkey_two = SECOND_VAL_PART_X_END_OF_VALUE\nformat = json",
		},
		{
			// Spans without hljs classes must still concatenate, preserving
			// the existing split-secret behavior even when hljs spans are
			// present elsewhere in the document.
			name: "non-hljs sibling spans still concatenate",
			chunk: &sources.Chunk{Data: []byte(
				`<p><span style="color:red">SECRET_</span><span>FIRST_HALF_1234</span></p>`,
			)},
			want: "SECRET_FIRST_HALF_1234",
		},
		{
			// Various hljs-* class names (not just hljs-function) should
			// all trigger line boundaries.
			name: "multiple hljs class variants trigger boundaries",
			chunk: &sources.Chunk{Data: []byte(
				`<p>` +
					`<span class="hljs-keyword">const</span>` +
					`<span> x = </span>` +
					`<span class="hljs-string">"value_one"</span>` +
					`<span class="hljs-keyword">const</span>` +
					`<span> y = </span>` +
					`<span class="hljs-string">"value_two"</span>` +
					`</p>`,
			)},
			want: "const x =\n\"value_one\"\nconst y =\n\"value_two\"",
		},

		// --- Zero-width / invisible character stripping ---
		{
			// Zero-width spaces inserted between characters by rich text editors
			// are stripped so detector regexes can match the full token.
			name: "zero-width space stripped from secret",
			chunk: &sources.Chunk{Data: []byte("<p>TOKEN_\u200BABCDEF_1234</p>")},
			want: "TOKEN_ABCDEF_1234",
		},
		{
			// Multiple invisible codepoint types mixed into a single token.
			name: "multiple invisible character types stripped",
			chunk: &sources.Chunk{Data: []byte("<p>SECRET\u200C_VALUE\u00AD_HERE\u2060_END\uFEFF</p>")},
			want: "SECRET_VALUE_HERE_END",
		},

		// --- SVG xlink:href attribute extraction ---
		{
			// SVG elements use xlink:href for URLs which may contain tokens.
			name: "xlink:href extracted from SVG element",
			chunk: &sources.Chunk{Data: []byte(`<svg><a xlink:href="https://api.example.com?token=secret_value_123">icon</a></svg>`)},
			want: "https://api.example.com?token=secret_value_123\nicon",
		},

		// --- Double-encoded HTML entity decoding ---
		{
			// Content double-encoded as &amp;amp; becomes &amp; after the parser's
			// first pass; the residual entity replacer decodes it to &.
			name: "double-encoded ampersand decoded",
			chunk: &sources.Chunk{Data: []byte(`<p>key=abc&amp;amp;secret=val</p>`)},
			want: "key=abc&secret=val",
		},
		{
			// Single-encoded entities are handled by the parser; verify the
			// residual replacer does not corrupt already-decoded content.
			name: "single-encoded entities not double-decoded",
			chunk: &sources.Chunk{Data: []byte(`<p>5 &gt; 3 &amp; 2 &lt; 4</p>`)},
			want: "5 > 3 & 2 < 4",
		},

		// --- Integration: all extraction types in one chunk ---
		{
			// Combines text nodes (split across spans), URL-decoded attribute
			// values, inline script content, and an HTML comment -- all in a
			// single chunk. Verifies the decoder handles the full extraction
			// surface simultaneously.
			name: "mixed content with all extraction types",
			chunk: &sources.Chunk{Data: []byte(
				`<p>API key: <span style="color:red">AKIA</span><span>1234567890ABCDEF</span></p>` +
					`<p>See <a href="https://api.example.com?token=sk%2Dlive%5F1234">docs</a></p>` +
					`<script>var secret = "ghp_abc123def456";</script>` +
					`<!-- TODO: remove hardcoded password=hunter2 -->`,
			)},
			want: "API key: AKIA1234567890ABCDEF\nSee\nhttps://api.example.com?token=sk-live_1234\ndocs\nvar secret = \"ghp_abc123def456\";\nTODO: remove hardcoded password=hunter2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feature.HTMLDecoderEnabled.Store(true)
			defer feature.HTMLDecoderEnabled.Store(false)

			d := &HTML{}
			got := d.FromChunk(tt.chunk)

			if tt.wantNil {
				if got != nil {
					t.Errorf("FromChunk() = %q, want nil", string(got.Chunk.Data))
				}
				return
			}

			if got == nil {
				t.Fatalf("FromChunk() returned nil, want %q", tt.want)
			}
			if got.DecoderType != detectorspb.DecoderType_HTML {
				t.Errorf("DecoderType = %v, want %v", got.DecoderType, detectorspb.DecoderType_HTML)
			}
			if string(got.Chunk.Data) != tt.want {
				t.Errorf("FromChunk() data =\n%q\nwant:\n%q", string(got.Chunk.Data), tt.want)
			}
		})
	}
}

// TestHTML_FeatureFlagDisabled verifies that the decoder is a no-op when
// feature.HTMLDecoderEnabled is false.
func TestHTML_FeatureFlagDisabled(t *testing.T) {
	feature.HTMLDecoderEnabled.Store(false)
	d := &HTML{}
	chunk := &sources.Chunk{Data: []byte(`<p>secret: hunter2</p>`)}
	if got := d.FromChunk(chunk); got != nil {
		t.Errorf("FromChunk() should return nil when disabled, got %q", string(got.Chunk.Data))
	}
}

// TestHTML_FeatureFlagEnabled verifies that the decoder processes HTML normally
// when feature.HTMLDecoderEnabled is true.
func TestHTML_FeatureFlagEnabled(t *testing.T) {
	feature.HTMLDecoderEnabled.Store(true)
	defer feature.HTMLDecoderEnabled.Store(false)

	d := &HTML{}
	chunk := &sources.Chunk{Data: []byte(`<p>secret: hunter2</p>`)}
	got := d.FromChunk(chunk)
	if got == nil {
		t.Fatal("FromChunk() returned nil, want decoded chunk")
	}
	if string(got.Chunk.Data) != "secret: hunter2" {
		t.Errorf("FromChunk() data = %q, want %q", string(got.Chunk.Data), "secret: hunter2")
	}
}

// TestLooksLikeHTML verifies the fast heuristic that decides whether chunk data
// is worth parsing as HTML. It must accept valid HTML tags (including self-closing
// and attribute-bearing) while rejecting plain text, arithmetic comparisons, and
// bare HTML entities -- all of which could appear in non-HTML source content.
func TestLooksLikeHTML(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"simple tag", "<p>hello</p>", true},
		{"self-closing", "<br/>", true},
		{"with attributes", `<div class="foo">`, true},
		{"plain text", "no html here", false},
		{"angle brackets but not HTML", "5 < 10 and 20 > 15", false},
		{"XML-like", "<root>content</root>", true},
		{"just less-than", "a < b", false},
		{"html entity only", "&amp; &lt;", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeHTML([]byte(tt.data)); got != tt.want {
				t.Errorf("looksLikeHTML(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

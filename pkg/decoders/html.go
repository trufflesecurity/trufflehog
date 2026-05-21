package decoders

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// HTML is a decoder that extracts textual content from HTML documents.
// It produces a normalized view containing visible text, attribute values,
// script/style content, and HTML comments with entities and URL-encoding decoded.
// Gated at runtime by feature.HTMLDecoderEnabled.
type HTML struct{}

func (d *HTML) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_HTML
}

var htmlTagPattern = regexp.MustCompile(`<[a-zA-Z][a-zA-Z0-9]*[\s>/]`)

// highSignalAttrs are attribute names whose values are extracted into the
// decoded output because they commonly contain URLs, tokens, or other secrets.
var highSignalAttrs = map[string]bool{
	"href":       true,
	"src":        true,
	"action":     true,
	"value":      true,
	"content":    true,
	"alt":   true,
	"title": true,
}

// syntaxHighlightPrefixes lists CSS class prefixes used by syntax highlighting
// libraries. Elements with these classes mark logical line boundaries in code
// blocks where the platform (e.g. Teams) strips actual newlines.
var syntaxHighlightPrefixes = []string{"hljs-"}

// residualEntityReplacer decodes common HTML entities that survive double-encoding.
// When content is entity-encoded twice (e.g. &amp;amp;), the parser's first pass
// leaves residual entity sequences that this replacer cleans up.
var residualEntityReplacer = strings.NewReplacer(
	"&amp;", "&",
	"&lt;", "<",
	"&gt;", ">",
	"&quot;", `"`,
	"&#39;", "'",
	"&apos;", "'",
)

// invisibleReplacer strips zero-width and invisible Unicode codepoints that
// rich text editors may insert between characters, breaking detector regexes.
var invisibleReplacer = strings.NewReplacer(
	"\u200B", "", // zero-width space
	"\u200C", "", // zero-width non-joiner
	"\u200D", "", // zero-width joiner
	"\uFEFF", "", // byte order mark / zero-width no-break space
	"\u00AD", "", // soft hyphen
	"\u2060", "", // word joiner
	"\u200E", "", // left-to-right mark
	"\u200F", "", // right-to-left mark
)

// blockElements insert newline boundaries when encountered during extraction.
var blockElements = map[string]bool{
	"p": true, "div": true, "br": true, "hr": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"li": true, "ol": true, "ul": true,
	"tr": true, "td": true, "th": true, "table": true, "thead": true, "tbody": true, "tfoot": true,
	"blockquote": true, "section": true, "article": true, "header": true, "footer": true,
	"pre": true, "address": true, "figcaption": true, "figure": true,
	"details": true, "summary": true, "main": true, "nav": true, "aside": true,
	"form": true, "fieldset": true, "legend": true,
	"dd": true, "dt": true, "dl": true,
	"script": true, "style": true,
}

// rawTextElements are elements whose content the HTML parser treats as raw
// text (entities are NOT decoded). Residual entity decoding must be skipped
// for text nodes inside these elements to avoid corrupting literal sequences
// like &amp; in JavaScript.
var rawTextElements = map[string]bool{
	"script": true,
	"style":  true,
}

func (d *HTML) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	if !feature.HTMLDecoderEnabled.Load() {
		return nil
	}
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	if !looksLikeHTML(chunk.Data) {
		return nil
	}

	extracted := extractHTML(chunk.Data)
	if len(extracted) == 0 {
		return nil
	}

	if bytes.Equal(chunk.Data, extracted) {
		return nil
	}

	chunk.Data = extracted
	return &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
}

func looksLikeHTML(data []byte) bool {
	return htmlTagPattern.Match(data)
}

func extractHTML(data []byte) []byte {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	var buf bytes.Buffer
	buf.Grow(len(data))

	walkNode(&buf, doc, false)

	result := stripInvisible(buf.Bytes())
	return normalizeWhitespace(result)
}

func walkNode(buf *bytes.Buffer, n *html.Node, inRawText bool) {
	switch n.Type {
	case html.TextNode:
		text := n.Data
		if text != "" {
			if !inRawText {
				text = residualEntityReplacer.Replace(text)
			}
			buf.WriteString(text)
		}

	case html.CommentNode:
		if content := strings.TrimSpace(n.Data); content != "" {
			ensureNewline(buf)
			buf.WriteString(content)
			ensureNewline(buf)
		}

	case html.ElementNode:
		isBlock := blockElements[n.Data]

		if isBlock {
			ensureNewline(buf)
		} else if hasSyntaxHighlightClass(n) {
			ensureNewline(buf)
		}

		emitAttributes(buf, n)

		childRaw := inRawText || rawTextElements[n.Data]
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(buf, c, childRaw)
		}

		if isBlock {
			ensureNewline(buf)
		}

	default:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walkNode(buf, c, inRawText)
		}
	}
}

func hasSyntaxHighlightClass(n *html.Node) bool {
	for _, attr := range n.Attr {
		if attr.Key != "class" {
			continue
		}
		for _, cls := range strings.Fields(attr.Val) {
			for _, prefix := range syntaxHighlightPrefixes {
				if strings.HasPrefix(cls, prefix) {
					return true
				}
			}
		}
	}
	return false
}

func emitAttributes(buf *bytes.Buffer, n *html.Node) {
	for _, attr := range n.Attr {
		isDataAttr := strings.HasPrefix(attr.Key, "data-")
		if !highSignalAttrs[attr.Key] && !isDataAttr {
			continue
		}
		val := strings.TrimSpace(attr.Val)
		if val == "" || val == "#" {
			continue
		}
		decoded, err := url.PathUnescape(val)
		if err == nil && decoded != val {
			val = decoded
		}
		ensureNewline(buf)
		buf.WriteString(val)
		ensureNewline(buf)
	}
}

func ensureNewline(buf *bytes.Buffer) {
	if buf.Len() == 0 {
		return
	}
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
}

func stripInvisible(data []byte) []byte {
	return []byte(invisibleReplacer.Replace(string(data)))
}

// normalizeWhitespace collapses runs of blank lines and trims leading/trailing whitespace.
func normalizeWhitespace(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))
	var result [][]byte
	prevBlank := true
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			if !prevBlank {
				prevBlank = true
			}
			continue
		}
		if prevBlank && len(result) > 0 {
			result = append(result, []byte(""))
		}
		result = append(result, trimmed)
		prevBlank = false
	}
	return bytes.Join(result, []byte("\n"))
}

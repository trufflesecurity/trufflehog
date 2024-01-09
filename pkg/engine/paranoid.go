package engine

import (
	_ "embed"
	"fmt"
	"math"
	"path"
	"regexp"
	"strings"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/lexers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	// "github.com/trustelem/zxcvbn"
)

//go:embed words.txt
var wordsTxt string

//go:embed words_short.txt
var wordsShortTxt string

type ParanoidCore struct {
	Detectors         []detectors.Detector
	TokenLengthLookup map[int][]detectors.Detector
	IgnorePaths       []*regexp.Regexp
	ShortWordList     []string
	WordList          []string
	LongestWord       int
}

func NewParanoidCore(ds []detectors.Detector) *ParanoidCore {
	pc := &ParanoidCore{
		Detectors:         []detectors.Detector{},
		TokenLengthLookup: make(map[int][]detectors.Detector),
		WordList:          getWords(wordsTxt),
		ShortWordList:     getWords(wordsShortTxt),
		LongestWord:       100,
	}
	for _, d := range ds {
		paranoidDetector, ok := d.(detectors.Paranoid)
		if ok {
			pc.Detectors = append(pc.Detectors, d)
			for _, cred := range paranoidDetector.About().Credentials {
				if cred.CharacterMax > pc.LongestWord {
					pc.LongestWord = cred.CharacterMax
				}
				for i := cred.CharacterMin; i <= cred.CharacterMax; i++ {
					pc.TokenLengthLookup[i] = append(pc.TokenLengthLookup[i], d)
				}
			}
		}
	}

	return pc
}

type ParanoidDetector struct {
	targets  []string
	detector detectors.Detector
}

func (pc *ParanoidCore) getParanoidDetectors(targets []string) []ParanoidDetector {
	detectorMap := make(map[detectors.Detector]*ParanoidDetector)

	for _, target := range targets {
		targetLen := len(target)
		if detectors, exists := pc.TokenLengthLookup[targetLen]; exists {
			for _, detector := range detectors {
				if pd, found := detectorMap[detector]; found {
					// Append the target to the existing detector's targets
					pd.targets = append(pd.targets, target)
				} else {
					// Create a new ParanoidDetector and add it to the map
					detectorMap[detector] = &ParanoidDetector{
						targets:  []string{target},
						detector: detector,
					}
				}
			}
		}
	}

	// Convert the map to a slice
	paranoidDetectors := make([]ParanoidDetector, 0, len(detectorMap))
	for _, pd := range detectorMap {
		paranoidDetectors = append(paranoidDetectors, *pd)
	}

	return paranoidDetectors
}

func (pc *ParanoidCore) checks(word string, entropy float32) bool {
	if len(word) > pc.LongestWord {
		return false
	}
	if containsNWordsFromList(word, pc.WordList, 1) {
		return false
	}
	if containsNWordsFromList(word, pc.ShortWordList, 5) {
		return false
	}
	// TODO tomorrow
	// - Check for regular expression capture groups (e.g. [a-zA-Z0-9]{40})
	// - Check for 3 or more consecutive consonants
	if ShannonEntropy(word) < float64(entropy) {
		return false
	}

    // NOTE: zxcvbn significantly slows down the scan
	// if zxcvbn.PasswordStrength(word, nil).Score < 3 {
	// 	return false
	// }

	return true
}

func (pc *ParanoidCore) getFileInfo(chunk *sources.Chunk) (string, string) {
	fileType := ""
	filePath := ""
	if chunk.SourceType == sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM {
		filesystemChunk := chunk.SourceMetadata.GetData().(*source_metadatapb.MetaData_Filesystem)
		fileType = path.Ext(filesystemChunk.Filesystem.File)
		filePath = filesystemChunk.Filesystem.File
	} else if chunk.SourceType == sourcespb.SourceType_SOURCE_TYPE_GIT {
		gitChunk := chunk.SourceMetadata.GetData().(*source_metadatapb.MetaData_Git)
		fileType = path.Ext(gitChunk.Git.File)
		filePath = gitChunk.Git.File
	}
	return fileType, filePath
}

func (pc *ParanoidCore) inspect(data string, entropy float32, chunk *sources.Chunk) []string {
	fileType, filePath := pc.getFileInfo(chunk)
	// if anyRegexMatch(filePath, pc.IgnorePaths) {
	// 	return []string{}
	// }

	var l chroma.Lexer
	if fileType != "" {
		l = lexers.Get(fileType)
		if l == nil {
			return pc.inspectNoLexer(data, entropy, filePath)
		}
		return pc.inspectLexer(data, entropy, filePath, l)
		// } TODO might need this else {
		// 	l = lexers.Analyse(data)
		// }
	}
	return pc.inspectNoLexer(data, entropy, filePath)
}

func (pc *ParanoidCore) inspectLexer(data string, entropy float32, filePath string, l chroma.Lexer) []string {
	targets := []string{}
	if l.Config().Name != "plaintext" && l.Config().Name != "markdown" {
		iterator, err := l.Tokenise(nil, data)
		if err != nil {
			fmt.Println("error: ", err)
		}
		for _, token := range iterator.Tokens() {
			if token.Type == chroma.Comment ||
				token.Type == chroma.CommentMultiline ||
				token.Type == chroma.CommentPreproc ||
				token.Type == chroma.CommentSingle ||
				token.Type == chroma.CommentSpecial ||
				token.Type == chroma.LiteralString {
				words := strings.Split(token.Value, " ")
				for _, word := range words {
					word = strings.Trim(word, "\n")

					// check if word has a detector entry in token length lookup
					if _, ok := pc.TokenLengthLookup[len(word)]; !ok {
						continue
					}

					if !pc.checks(word, entropy) {
						continue
					}

					targets = append(targets, word)
				}
			}
		}
		return targets
	}
	return pc.inspectNoLexer(data, entropy, filePath)

}

func (pc *ParanoidCore) inspectNoLexer(data string, entropy float32, filePath string) []string {
	targets := []string{}
	// likely plaintext since no lexer was found
	words := strings.Fields(data) // split the data by whitespace
	for _, word := range words {
		word = strings.TrimSpace(word)
		word = strings.Trim(word, "\"")
		if !pc.checks(word, entropy) {
			continue
		}
		targets = append(targets, word)
	}
	return targets
}

func containsNWordsFromList(s string, list []string, n int) bool {
	count := 0
	s = strings.ToLower(s)
	for _, word := range list {
		if strings.Contains(s, word) {
			count++
			if count >= n {
				return true
			}
		}
	}
	return false
}

func ShannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// NOTE: This function is not used in the current implementation
// but based on some tests it might be a good idea to include it in the future
func countTripleConsonants(word string) int {
	// Define a regular expression for three or more consecutive consonants
	re := regexp.MustCompile(`(?i)[bcdfghjklmnpqrstvwxyz]{3,}`)
	matches := re.FindAllString(word, -1)

	// Initialize the count of occurrences
	count := 0
	for _, match := range matches {
		// Increase the count by 1 for each three consecutive consonants,
		// and by 1 more for each additional consecutive consonant
		count += len(match) - 2
	}

	return count
}

func anyRegexMatch(f string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if regexMatched(f, re) {
			return true
		}
	}
	return false
}

func regexMatched(f string, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if re.FindString(f) != "" {
		return true
	}
	return false
}

func getWords(s string) []string {
	rawWords := strings.Split(s, "\n")
	var words []string // Initialize an empty slice to hold the filtered words

	for _, word := range rawWords {
		trimmedWord := strings.TrimSpace(strings.ToLower(word))
		if trimmedWord != "" && !strings.Contains(trimmedWord, " ") {
			words = append(words, trimmedWord) // Append the word to the words slice if it's non-empty and doesn't contain spaces
		}
	}
	return words
}

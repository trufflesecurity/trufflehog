package common

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const EmailPattern = `\b([a-z0-9]{4,25}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\b`
const SubDomainPattern = `\b([0-9a-zA-Z]{2,40}.[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\b`
const UUIDPattern = `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`
const UUIDPatternUpperCase = `\b([0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12})\b`

const RegexPattern = "0-9a-z"
const AlphaNumPattern = "0-9a-zA-Z"
const HexPattern = "0-9a-f"

//Custom Regex functions
func BuildRegex(pattern string, specialChar string, length int) string {
	return fmt.Sprintf(`\b([%s%s]{%s})\b`, pattern, specialChar, strconv.Itoa(length))
}

func BuildRegexJWT(firstRange, secondRange, thirdRange string) string {
	first_range_split := strings.Split(firstRange, ",")
	first_range_min := strings.TrimSpace(first_range_split[0])
	first_range_max := strings.TrimSpace(first_range_split[1])
	if first_range_min >= first_range_max {
		log.Error("First min value should not be greater than or equal to max")
	}

	second_range_split := strings.Split(secondRange, ",")
	second_range_min := strings.TrimSpace(second_range_split[0])
	second_range_max := strings.TrimSpace(second_range_split[1])
	if second_range_min >= second_range_max {
		log.Error("Second min value should not be greater than or equal to max")
	}

	third_range_split := strings.Split(thirdRange, ",")
	third_range_min := strings.TrimSpace(third_range_split[0])
	third_range_max := strings.TrimSpace(third_range_split[1])
	if third_range_min >= third_range_max {
		log.Error("Third min value should not be greater than or equal to max")
	}

	return fmt.Sprintf(`\b(ey[%s]{%s}.ey[%s-\/_]{%s}.[%s-\/_]{%s})\b`, AlphaNumPattern, firstRange, AlphaNumPattern, secondRange, AlphaNumPattern, thirdRange)
}

func ToUpperCase(input string) string {
	return strings.ToUpper(input)
}

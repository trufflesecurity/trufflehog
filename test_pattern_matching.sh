#!/bin/bash
# Test pattern matching for all 9 AI service detectors
# This tests the regex patterns against the example keys provided

echo "========================================="
echo "Testing AI Service Detector Patterns"
echo "========================================="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PASS=0
FAIL=0

# Function to test if a pattern matches
test_pattern() {
    local pattern=$1
    local test_string=$2
    local desc=$3
    
    if echo "$test_string" | grep -qE "$pattern"; then
        echo -e "${GREEN}✓${NC} $desc - Pattern matches"
        ((PASS++))
        return 0
    else
        echo -e "${RED}✗${NC} $desc - Pattern does NOT match"
        echo "  Pattern: $pattern"
        echo "  Test string: $test_string"
        ((FAIL++))
        return 1
    fi
}

echo "1. Testing Exa AI Pattern"
echo "-------------------------"
EXA_PATTERN='[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
EXA_KEY="a7c7cd0f-2718-4a39-8e44-90cd4507d24e"
test_pattern "$EXA_PATTERN" "$EXA_KEY" "Exa AI UUID format"
echo ""

echo "2. Testing FireCrawl Pattern"
echo "----------------------------"
FIRECRAWL_PATTERN='fc-[a-f0-9]{32}'
FIRECRAWL_KEY="fc-5b42b80e75ad4537b5ac00e67f04ddec"
test_pattern "$FIRECRAWL_PATTERN" "$FIRECRAWL_KEY" "FireCrawl fc- prefix"
echo ""

echo "3. Testing Perplexity Pattern"
echo "-----------------------------"
PERPLEXITY_PATTERN='pplx-[A-Za-z0-9]{48}'
PERPLEXITY_KEY="pplx-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
test_pattern "$PERPLEXITY_PATTERN" "$PERPLEXITY_KEY" "Perplexity pplx- prefix"
echo ""

echo "4. Testing OpenRouter Pattern"
echo "-----------------------------"
OPENROUTER_PATTERN='sk-or-v1-[a-f0-9]{64}'
OPENROUTER_KEY="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"
test_pattern "$OPENROUTER_PATTERN" "$OPENROUTER_KEY" "OpenRouter sk-or-v1- prefix"
echo ""

echo "5. Testing Google Gemini Pattern"
echo "--------------------------------"
GEMINI_PATTERN='AIza[A-Za-z0-9_-]{34,39}'
GEMINI_KEY="AIzaSyBK7vFZ9w3N4xyH2qK8mL9eR7tU1pQ3cV"
test_pattern "$GEMINI_PATTERN" "$GEMINI_KEY" "Google Gemini AIza prefix"
echo ""

echo "6. Testing Runway ML Pattern"
echo "----------------------------"
RUNWAY_PATTERN='key_[a-f0-9]{128}'
RUNWAY_KEY="key_283667ea00cb246b0806b2d9daebc89834003d3e4d15c4d05b7d747d154dc2cb77bdd5dd8059bf1be716eac634ae988dddda01e966aba2715cea85a0c737db54"
test_pattern "$RUNWAY_PATTERN" "$RUNWAY_KEY" "Runway ML key_ prefix"
echo ""

echo "7. Testing Google Veo Pattern"
echo "-----------------------------"
VEO_PATTERN='AIza[A-Za-z0-9_-]{34,39}'
VEO_KEY="AIzaSyBK7vFZ9w3N4xyH2qK8mL9eR7tU1pQ3cV"
test_pattern "$VEO_PATTERN" "$VEO_KEY" "Google Veo AIza prefix"
echo ""

echo "8. Testing HeyGen Pattern"
echo "-------------------------"
HEYGEN_PATTERN='sk_V2_[A-Za-z0-9_]{40,50}'
HEYGEN_KEY="sk_V2_hgu_kd4QiCepP48_TyrBy2RTad5TcAox1VkhegJIfzPaTQ5x"
test_pattern "$HEYGEN_PATTERN" "$HEYGEN_KEY" "HeyGen sk_V2_ prefix"
echo ""

echo "9. Testing MidJourney Pattern"
echo "-----------------------------"
MIDJOURNEY_PATTERN='[a-f0-9]{32}'
MIDJOURNEY_KEY="4aa8b6f09ad58100c3ad9d4a61f0f03a"
test_pattern "$MIDJOURNEY_PATTERN" "$MIDJOURNEY_KEY" "MidJourney 32-char hex"
echo ""

echo "========================================="
echo "Pattern Matching Summary"
echo "========================================="
echo -e "${GREEN}Passed:${NC} $PASS/9 patterns"
echo -e "${RED}Failed:${NC} $FAIL/9 patterns"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ All patterns match their example keys!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some patterns don't match. Review implementations.${NC}"
    exit 1
fi


#!/bin/bash
# Validation script for AI service detectors
# This script validates the implementations without requiring Go

echo "=================================="
echo "AI Service Detectors Validation"
echo "=================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counter for results
PASS=0
FAIL=0

# Function to check if file exists and has content
check_file() {
    local file=$1
    local desc=$2
    
    if [ -f "$file" ]; then
        if [ -s "$file" ]; then
            echo -e "${GREEN}✓${NC} $desc exists and has content"
            ((PASS++))
            return 0
        else
            echo -e "${RED}✗${NC} $desc is empty"
            ((FAIL++))
            return 1
        fi
    else
        echo -e "${RED}✗${NC} $desc not found"
        ((FAIL++))
        return 1
    fi
}

# Function to check if pattern exists in file
check_pattern() {
    local file=$1
    local pattern=$2
    local desc=$3
    
    if grep -q "$pattern" "$file"; then
        echo -e "${GREEN}✓${NC} $desc"
        ((PASS++))
        return 0
    else
        echo -e "${RED}✗${NC} $desc not found"
        ((FAIL++))
        return 1
    fi
}

echo "1. Checking Detector Files..."
echo "-----------------------------"
check_file "pkg/detectors/exaai/exaai.go" "Exa AI detector"
check_file "pkg/detectors/firecrawl/firecrawl.go" "FireCrawl detector"
check_file "pkg/detectors/perplexity/perplexity.go" "Perplexity detector"
check_file "pkg/detectors/openrouter/openrouter.go" "OpenRouter detector"
check_file "pkg/detectors/googlegemini/googlegemini.go" "Google Gemini detector"
check_file "pkg/detectors/runwayml/runwayml.go" "Runway ML detector"
check_file "pkg/detectors/googleveo/googleveo.go" "Google Veo detector"
check_file "pkg/detectors/heygen/heygen.go" "HeyGen detector"
check_file "pkg/detectors/midjourney/midjourney.go" "MidJourney detector"
echo ""

echo "2. Checking Test Files..."
echo "-------------------------"
check_file "pkg/detectors/exaai/exaai_test.go" "Exa AI tests"
check_file "pkg/detectors/firecrawl/firecrawl_test.go" "FireCrawl tests"
check_file "pkg/detectors/perplexity/perplexity_test.go" "Perplexity tests"
check_file "pkg/detectors/openrouter/openrouter_test.go" "OpenRouter tests"
check_file "pkg/detectors/googlegemini/googlegemini_test.go" "Google Gemini tests"
check_file "pkg/detectors/runwayml/runwayml_test.go" "Runway ML tests"
check_file "pkg/detectors/googleveo/googleveo_test.go" "Google Veo tests"
check_file "pkg/detectors/heygen/heygen_test.go" "HeyGen tests"
check_file "pkg/detectors/midjourney/midjourney_test.go" "MidJourney tests"
echo ""

echo "3. Checking Regex Patterns..."
echo "-----------------------------"
check_pattern "pkg/detectors/exaai/exaai.go" "\[a-f0-9\]{8}-\[a-f0-9\]{4}" "Exa AI UUID pattern"
check_pattern "pkg/detectors/firecrawl/firecrawl.go" "fc-\[a-f0-9\]{32}" "FireCrawl pattern"
check_pattern "pkg/detectors/perplexity/perplexity.go" "pplx-\[A-Za-z0-9\]{48}" "Perplexity pattern"
check_pattern "pkg/detectors/openrouter/openrouter.go" "sk-or-v1-\[a-f0-9\]{64}" "OpenRouter pattern"
check_pattern "pkg/detectors/googlegemini/googlegemini.go" "AIza\[A-Za-z0-9_-\]{35}" "Google Gemini pattern"
check_pattern "pkg/detectors/runwayml/runwayml.go" "key_\[a-f0-9\]{128}" "Runway ML pattern"
check_pattern "pkg/detectors/googleveo/googleveo.go" "AIza\[A-Za-z0-9_-\]{35}" "Google Veo pattern"
check_pattern "pkg/detectors/heygen/heygen.go" "sk_V2_\[A-Za-z0-9_\]{40,50}" "HeyGen pattern"
check_pattern "pkg/detectors/midjourney/midjourney.go" "\[a-f0-9\]{32}" "MidJourney pattern"
echo ""

echo "4. Checking Verification Endpoints..."
echo "-------------------------------------"
check_pattern "pkg/detectors/exaai/exaai.go" "api.exa.ai" "Exa AI endpoint"
check_pattern "pkg/detectors/firecrawl/firecrawl.go" "api.firecrawl.dev" "FireCrawl endpoint"
check_pattern "pkg/detectors/perplexity/perplexity.go" "api.perplexity.ai" "Perplexity endpoint"
check_pattern "pkg/detectors/openrouter/openrouter.go" "openrouter.ai" "OpenRouter endpoint"
check_pattern "pkg/detectors/googlegemini/googlegemini.go" "generativelanguage.googleapis.com" "Google Gemini endpoint"
check_pattern "pkg/detectors/runwayml/runwayml.go" "api.runwayml.com" "Runway ML endpoint"
check_pattern "pkg/detectors/googleveo/googleveo.go" "generativelanguage.googleapis.com" "Google Veo endpoint"
check_pattern "pkg/detectors/heygen/heygen.go" "api.heygen.com" "HeyGen endpoint"
echo ""

echo "5. Checking Keywords..."
echo "-----------------------"
check_pattern "pkg/detectors/exaai/exaai.go" 'Keywords.*exa' "Exa AI keywords"
check_pattern "pkg/detectors/firecrawl/firecrawl.go" 'Keywords.*fc-' "FireCrawl keywords"
check_pattern "pkg/detectors/perplexity/perplexity.go" 'Keywords.*pplx-' "Perplexity keywords"
check_pattern "pkg/detectors/openrouter/openrouter.go" 'Keywords.*sk-or-v1-' "OpenRouter keywords"
check_pattern "pkg/detectors/googlegemini/googlegemini.go" 'Keywords.*AIza' "Google Gemini keywords"
check_pattern "pkg/detectors/runwayml/runwayml.go" 'Keywords.*runway' "Runway ML keywords"
check_pattern "pkg/detectors/googleveo/googleveo.go" 'Keywords.*veo' "Google Veo keywords"
check_pattern "pkg/detectors/heygen/heygen.go" 'Keywords.*sk_V2_' "HeyGen keywords"
check_pattern "pkg/detectors/midjourney/midjourney.go" 'Keywords.*midjourney' "MidJourney keywords"
echo ""

echo "6. Checking Proto Definitions..."
echo "--------------------------------"
check_pattern "proto/detectors.proto" "ExaAI = 1040" "ExaAI proto enum"
check_pattern "proto/detectors.proto" "FireCrawl = 1041" "FireCrawl proto enum"
check_pattern "proto/detectors.proto" "Perplexity = 1042" "Perplexity proto enum"
check_pattern "proto/detectors.proto" "OpenRouter = 1043" "OpenRouter proto enum"
check_pattern "proto/detectors.proto" "GoogleGemini = 1044" "GoogleGemini proto enum"
check_pattern "proto/detectors.proto" "RunwayML = 1045" "RunwayML proto enum"
check_pattern "proto/detectors.proto" "GoogleVeo = 1046" "GoogleVeo proto enum"
check_pattern "proto/detectors.proto" "HeyGen = 1047" "HeyGen proto enum"
check_pattern "proto/detectors.proto" "MidJourney = 1048" "MidJourney proto enum"
echo ""

echo "7. Checking Engine Registration..."
echo "-----------------------------------"
check_pattern "pkg/engine/defaults/defaults.go" 'exaai"' "Exa AI import"
check_pattern "pkg/engine/defaults/defaults.go" 'firecrawl"' "FireCrawl import"
check_pattern "pkg/engine/defaults/defaults.go" 'perplexity"' "Perplexity import"
check_pattern "pkg/engine/defaults/defaults.go" 'openrouter"' "OpenRouter import"
check_pattern "pkg/engine/defaults/defaults.go" 'googlegemini"' "Google Gemini import"
check_pattern "pkg/engine/defaults/defaults.go" 'runwayml"' "Runway ML import"
check_pattern "pkg/engine/defaults/defaults.go" 'googleveo"' "Google Veo import"
check_pattern "pkg/engine/defaults/defaults.go" 'heygen"' "HeyGen import"
check_pattern "pkg/engine/defaults/defaults.go" 'midjourney"' "MidJourney import"
echo ""

check_pattern "pkg/engine/defaults/defaults.go" '&exaai.Scanner{}' "Exa AI scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&firecrawl.Scanner{}' "FireCrawl scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&perplexity.Scanner{}' "Perplexity scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&openrouter.Scanner{}' "OpenRouter scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&googlegemini.Scanner{}' "Google Gemini scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&runwayml.Scanner{}' "Runway ML scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&googleveo.Scanner{}' "Google Veo scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&heygen.Scanner{}' "HeyGen scanner registration"
check_pattern "pkg/engine/defaults/defaults.go" '&midjourney.Scanner{}' "MidJourney scanner registration"
echo ""

echo "=================================="
echo "Validation Summary"
echo "=================================="
echo -e "${GREEN}Passed:${NC} $PASS checks"
echo -e "${RED}Failed:${NC} $FAIL checks"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✓ All validations passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Install Go 1.24+ if not already installed"
    echo "2. Run: make protos"
    echo "3. Run: go test ./pkg/detectors/exaai -v"
    echo "4. Run tests for all other detectors"
    exit 0
else
    echo -e "${RED}✗ Some validations failed. Please review the errors above.${NC}"
    exit 1
fi


#!/bin/bash

# TruffleHog API Integration Test Script

API_URL="${API_URL:-http://localhost:8080}"
API_KEY="${API_KEY:-test-key-123}"

echo "================================================"
echo "TruffleHog API Integration Tests"
echo "================================================"
echo "API URL: $API_URL"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

test_count=0
passed_count=0
failed_count=0

# Test function
run_test() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local data="$4"
    local expected_status="$5"
    
    test_count=$((test_count + 1))
    echo -n "Test $test_count: $name... "
    
    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $API_KEY" \
            "$API_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $API_KEY" \
            -d "$data" \
            "$API_URL$endpoint")
    fi
    
    status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}PASS${NC} (Status: $status)"
        passed_count=$((passed_count + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC} (Expected: $expected_status, Got: $status)"
        echo "Response: $body"
        failed_count=$((failed_count + 1))
        return 1
    fi
}

echo "Running tests..."
echo ""

# Test 1: Health check
run_test "Health Check" "GET" "/health" "" "200"

# Test 2: Root endpoint
run_test "Root Endpoint" "GET" "/" "" "200"

# Test 3: List detectors
run_test "List Detectors" "GET" "/api/v1/detectors" "" "200"

# Test 4: Create scan job
scan_data='{"repo_url":"https://github.com/test/repo","branch":"main"}'
scan_response=$(run_test "Create Scan Job" "POST" "/api/v1/scan" "$scan_data" "202")

# Extract job ID from response (if test passed)
if [ $? -eq 0 ]; then
    job_id=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "$scan_data" \
        "$API_URL/api/v1/scan" | grep -o '"job_id":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$job_id" ]; then
        # Test 5: Get scan status
        run_test "Get Scan Status" "GET" "/api/v1/scan/$job_id" "" "200"
        
        # Test 6: Cancel scan
        run_test "Cancel Scan" "DELETE" "/api/v1/scan/$job_id" "" "200"
    fi
fi

# Test 7: Create webhook
webhook_data='{"url":"https://webhook.site/test","secret":"test-secret-123456","events":["scan.completed"]}'
run_test "Create Webhook" "POST" "/api/v1/webhooks" "$webhook_data" "201"

# Test 8: List webhooks
run_test "List Webhooks" "GET" "/api/v1/webhooks" "" "200"

# Test 9: Swagger UI
run_test "Swagger UI" "GET" "/swagger/" "" "200"

# Test 10: Invalid endpoint
run_test "Invalid Endpoint" "GET" "/api/v1/invalid" "" "404"

echo ""
echo "================================================"
echo "Test Results"
echo "================================================"
echo "Total Tests: $test_count"
echo -e "Passed: ${GREEN}$passed_count${NC}"
echo -e "Failed: ${RED}$failed_count${NC}"
echo ""

if [ $failed_count -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi


# TruffleHog AI Detectors - Build and Test Instructions

## Implementation Summary

Successfully implemented 9 new AI service detectors for TruffleHog:

1. ✅ **Exa AI** - UUID format detection and verification
2. ✅ **FireCrawl** - `fc-` prefixed key detection
3. ✅ **Perplexity** - `pplx-` prefixed key detection
4. ✅ **OpenRouter** - `sk-or-v1-` prefixed key detection
5. ✅ **Google Gemini AI** - Google AI Studio API key detection
6. ✅ **Runway ML** - `key_` prefixed 128-char hex key detection
7. ✅ **Google Veo** - Google AI Studio API key detection (Veo-specific)
8. ✅ **HeyGen** - `sk_V2_` prefixed key detection
9. ✅ **MidJourney** - 32-char hex token detection (unverified)

## Files Created

### Detector Implementations
- `pkg/detectors/exaai/exaai.go` + `exaai_test.go`
- `pkg/detectors/firecrawl/firecrawl.go` + `firecrawl_test.go`
- `pkg/detectors/perplexity/perplexity.go` + `perplexity_test.go`
- `pkg/detectors/openrouter/openrouter.go` + `openrouter_test.go`
- `pkg/detectors/googlegemini/googlegemini.go` + `googlegemini_test.go`
- `pkg/detectors/runwayml/runwayml.go` + `runwayml_test.go`
- `pkg/detectors/googleveo/googleveo.go` + `googleveo_test.go`
- `pkg/detectors/heygen/heygen.go` + `heygen_test.go`
- `pkg/detectors/midjourney/midjourney.go` + `midjourney_test.go`

### Files Modified
- `proto/detectors.proto` - Added 9 new detector type enums (1040-1048)
- `pkg/engine/defaults/defaults.go` - Added imports and registered all 9 detectors

## Building the Windows Executable

### Prerequisites
- Go 1.24+ installed (as specified in go.mod)
- Git for Windows (for bash shell)

### Option 1: Simple Build (Recommended)

```bash
# Navigate to project root
cd C:/Users/Yomen/trufflehog

# Build for Windows 64-bit
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o trufflehog.exe .
```

The executable will be created in the current directory as `trufflehog.exe`

### Option 2: Build with Version Info

```bash
# Build with version and optimization flags
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
  -ldflags="-s -w -X 'github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion=custom-v3.0.0'" \
  -o trufflehog.exe .
```

### Option 3: Multi-Platform Build with GoReleaser

```bash
# Install goreleaser if not already installed
go install github.com/goreleaser/goreleaser@latest

# Build for current platform only (faster)
goreleaser build --clean --snapshot --single-target

# Build for all platforms (slower)
goreleaser build --clean --snapshot
```

Windows executables will be in:
- `dist/trufflehog_windows_amd64_v1/trufflehog.exe` (64-bit)
- `dist/trufflehog_windows_arm64/trufflehog.exe` (ARM64)

## Testing

### Step 1: Generate Protobuf Files (Required Before Testing)

```bash
# Option 1: Using Docker (Recommended)
make protos

# Option 2: Using local protoc
cd proto
protoc --go_out=../pkg/pb --go_opt=paths=source_relative detectors.proto
cd ..
```

### Step 2: Run Unit Tests

Test all new detectors without API verification:

```bash
# Test individual detectors
go test ./pkg/detectors/exaai -v
go test ./pkg/detectors/firecrawl -v
go test ./pkg/detectors/perplexity -v
go test ./pkg/detectors/openrouter -v
go test ./pkg/detectors/googlegemini -v
go test ./pkg/detectors/runwayml -v
go test ./pkg/detectors/googleveo -v
go test ./pkg/detectors/heygen -v
go test ./pkg/detectors/midjourney -v

# Or test all at once
go test ./pkg/detectors/exaai ./pkg/detectors/firecrawl ./pkg/detectors/perplexity ./pkg/detectors/openrouter ./pkg/detectors/googlegemini ./pkg/detectors/runwayml ./pkg/detectors/googleveo ./pkg/detectors/heygen ./pkg/detectors/midjourney -v
```

### Step 3: Integration Tests with Real API Keys

Create `.env` files in each detector directory with your real API keys:

**Example: `pkg/detectors/exaai/.env`**
```bash
EXA_AI_KEY=your-exa-api-key-here
EXA_AI_KEY_INACTIVE=00000000-0000-0000-0000-000000000000
```

**Example: `pkg/detectors/firecrawl/.env`**
```bash
FIRECRAWL_KEY=fc-your-key-here
FIRECRAWL_KEY_INACTIVE=fc-00000000000000000000000000000000
```

**Example: `pkg/detectors/perplexity/.env`**
```bash
PERPLEXITY_KEY=pplx-your-key-here
PERPLEXITY_KEY_INACTIVE=pplx-000000000000000000000000000000000000000000000000
```

**Example: `pkg/detectors/openrouter/.env`**
```bash
OPENROUTER_KEY=sk-or-v1-your-key-here
OPENROUTER_KEY_INACTIVE=sk-or-v1-0000000000000000000000000000000000000000000000000000000000000000
```

**Example: `pkg/detectors/runway/.env`**
```bash
RUNWAY_KEY=key_your-key-here
RUNWAY_KEY_INACTIVE=key_0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

**Example: `pkg/detectors/heygen/.env`**
```bash
HEYGEN_KEY=sk_V2_your-key-here
HEYGEN_KEY_INACTIVE=sk_V2_0000000000000000000000000000000000000000
```

Then run integration tests:

```bash
# Set environment variable to point to test secrets
export TEST_SECRET_FILE=".env"

# Run integration tests for each detector
go test ./pkg/detectors/exaai -tags=detectors -v
go test ./pkg/detectors/firecrawl -tags=detectors -v
go test ./pkg/detectors/perplexity -tags=detectors -v
go test ./pkg/detectors/openrouter -tags=detectors -v
go test ./pkg/detectors/googlegemini -tags=detectors -v
go test ./pkg/detectors/runwayml -tags=detectors -v
go test ./pkg/detectors/googleveo -tags=detectors -v
go test ./pkg/detectors/heygen -tags=detectors -v
go test ./pkg/detectors/midjourney -tags=detectors -v
```

### Step 4: Test the Built Executable

Create a test file with API keys:

```bash
# Create test file (replace with your actual API keys)
cat > test_secrets.txt << 'EOF'
EXA_API_KEY=your-exa-api-key-here
FIRECRAWL_KEY=fc-your-key-here
PERPLEXITY_API=pplx-your-key-here
OPENROUTER_KEY=sk-or-v1-your-key-here
RUNWAY_KEY=key_your-key-here
HEYGEN_API_KEY=sk_V2_your-key-here
MIDJOURNEY_TOKEN=your-midjourney-token-here
EOF

# Test with the executable
./trufflehog.exe filesystem test_secrets.txt --results=verified

# Or scan a directory
./trufflehog.exe filesystem . --results=verified,unknown
```

## Verification API Endpoints

Each detector uses these endpoints for verification:

| Service | Endpoint | Method | Header |
|---------|----------|--------|--------|
| Exa AI | `https://api.exa.ai/search` | POST | `x-api-key` |
| FireCrawl | `https://api.firecrawl.dev/v1/crawl/status/test` | GET | `Authorization: Bearer` |
| Perplexity | `https://api.perplexity.ai/models` | GET | `Authorization: Bearer` |
| OpenRouter | `https://openrouter.ai/api/v1/auth/key` | GET | `Authorization: Bearer` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1/models?key=KEY` | GET | Query param |
| Runway ML | `https://api.runwayml.com/v1/users/me` | GET | `Authorization: Bearer` |
| Google Veo | `https://generativelanguage.googleapis.com/v1/models?key=KEY` | GET | Query param |
| HeyGen | `https://api.heygen.com/v1/user.get` | GET | `X-Api-Key` |
| MidJourney | N/A | N/A | No official API |

## Troubleshooting

### Proto Generation Issues
If you get protobuf-related errors:
```bash
# Ensure Docker is running
docker --version

# Run proto generation
make protos

# Or manually with Docker
docker run --rm -v "${PWD}:/pwd" trufflesecurity/protos:1.22 bash -c "cd /pwd; /pwd/scripts/gen_proto.sh"
```

### Build Issues
```bash
# Clear Go cache
go clean -cache -modcache

# Re-download dependencies
go mod download

# Verify Go version
go version  # Should be 1.24+

# Try build again
go build -o trufflehog.exe .
```

### Test Failures
```bash
# Ensure you're in project root
cd C:/Users/Yomen/trufflehog

# Run with verbose output
go test ./pkg/detectors/exaai -v -count=1

# Skip cache
go test ./pkg/detectors/exaai -v -count=1
```

## Next Steps

1. ✅ **Generate protobuf files** (Required)
   ```bash
   make protos
   ```

2. ✅ **Build the executable**
   ```bash
   go build -o trufflehog.exe .
   ```

3. ✅ **Run basic tests**
   ```bash
   go test ./pkg/detectors/exaai -v
   ```

4. ✅ **Test with real keys** (Optional but recommended)
   - Create `.env` files with your API keys
   - Run integration tests

5. ✅ **Verify the executable works**
   ```bash
   ./trufflehog.exe filesystem test_secrets.txt
   ```

## Success Criteria

- ✅ All 9 detector implementations created
- ✅ All 9 test files created
- ✅ All detectors registered in engine
- ⏳ Protobuf files generated (requires: `make protos`)
- ⏳ Unit tests pass (requires: proto generation)
- ⏳ Windows executable built (requires: Go toolchain)
- ⏳ Integration tests pass with real keys (optional)

## Support

If you encounter any issues:
1. Ensure Go 1.24+ is installed
2. Ensure Docker is running (for proto generation)
3. Check that all dependencies are downloaded: `go mod download`
4. Verify the proto files are generated: check `pkg/pb/detectorspb/detectors.pb.go`


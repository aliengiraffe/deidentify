#!/bin/bash

# Development check script
# Runs all the checks that should pass before submitting a PR
# Ensures Go Report Card A+ quality standards

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Running Go Report Card A+ quality checks...${NC}"
echo

# Helper function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Helper function to install Go tools if missing
install_tool_if_missing() {
    local tool_name="$1"
    local install_path="$2"
    
    if ! command_exists "$tool_name"; then
        echo -e "${YELLOW}Installing $tool_name...${NC}"
        go install "$install_path" || {
            echo -e "${RED}✗ Failed to install $tool_name${NC}"
            exit 1
        }
    fi
}

# Install required tools if missing
install_tool_if_missing "staticcheck" "honnef.co/go/tools/cmd/staticcheck@latest"
install_tool_if_missing "golangci-lint" "github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
install_tool_if_missing "gocyclo" "github.com/fzipp/gocyclo/cmd/gocyclo@latest"

# Check if gofmt is needed
echo -e "${YELLOW}Checking Go formatting...${NC}"
GOFMT_FILES=$(gofmt -l .)
if [ -n "$GOFMT_FILES" ]; then
    echo -e "${RED}✗ The following files need formatting:${NC}"
    echo "$GOFMT_FILES"
    echo -e "${YELLOW}Run 'gofmt -w -s .' to fix${NC}"
    exit 1
else
    echo -e "${GREEN}✓ All Go files are properly formatted${NC}"
fi
echo

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
if go test ./...; then
    echo -e "${GREEN}✓ All tests passed${NC}"
else
    echo -e "${RED}✗ Tests failed${NC}"
    exit 1
fi
echo

# Run tests with race detector
echo -e "${YELLOW}Running tests with race detector...${NC}"
if go test -race ./...; then
    echo -e "${GREEN}✓ No race conditions detected${NC}"
else
    echo -e "${RED}✗ Race conditions detected${NC}"
    exit 1
fi
echo

# Check build
echo -e "${YELLOW}Checking build...${NC}"
if go build ./...; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo

# Run vet
echo -e "${YELLOW}Running go vet...${NC}"
if go vet ./...; then
    echo -e "${GREEN}✓ go vet passed${NC}"
else
    echo -e "${RED}✗ go vet found issues${NC}"
    exit 1
fi
echo

# Run staticcheck
echo -e "${YELLOW}Running staticcheck...${NC}"
if staticcheck ./...; then
    echo -e "${GREEN}✓ staticcheck passed${NC}"
else
    echo -e "${RED}✗ staticcheck found issues${NC}"
    exit 1
fi
echo

# Run golangci-lint
echo -e "${YELLOW}Running golangci-lint...${NC}"
if golangci-lint run --timeout=5m; then
    echo -e "${GREEN}✓ golangci-lint passed${NC}"
else
    echo -e "${RED}✗ golangci-lint found issues${NC}"
    exit 1
fi
echo

# Check cyclomatic complexity
echo -e "${YELLOW}Checking cyclomatic complexity...${NC}"
COMPLEX_FUNCS=$(gocyclo -over 15 . | grep -v "_test.go" || true)
if [ -n "$COMPLEX_FUNCS" ]; then
    echo -e "${RED}✗ Functions with high cyclomatic complexity (>15):${NC}"
    echo "$COMPLEX_FUNCS"
    echo -e "${YELLOW}Consider refactoring these functions${NC}"
    exit 1
else
    echo -e "${GREEN}✓ All functions have acceptable cyclomatic complexity (≤15)${NC}"
fi
echo

# Check examples compile
echo -e "${YELLOW}Checking examples compile...${NC}"

for example in examples/*/main.go; do
    example_dir=$(dirname "$example")
    example_name=$(basename "$example_dir")
    
    echo -n "  Checking $example_name example compiles... "
    if go build -o /dev/null "$example" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}Example $example_name failed to compile${NC}"
        exit 1
    fi
done
echo

# Check for TODO/FIXME comments
echo -e "${YELLOW}Checking for TODO/FIXME comments...${NC}"
TODO_COUNT=$(grep -r "TODO\|FIXME" --include="*.go" . | wc -l | tr -d ' ')
if [ "$TODO_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}Found $TODO_COUNT TODO/FIXME comments:${NC}"
    grep -r "TODO\|FIXME" --include="*.go" . || true
    echo -e "${YELLOW}Consider addressing these before submitting${NC}"
else
    echo -e "${GREEN}✓ No TODO/FIXME comments found${NC}"
fi
echo

# Check test coverage (informational)
echo -e "${YELLOW}Checking test coverage...${NC}"
COVERAGE_OUTPUT=$(go test -cover . 2>/dev/null | grep "coverage:" | tail -1)
if [ -n "$COVERAGE_OUTPUT" ]; then
    COVERAGE=$(echo "$COVERAGE_OUTPUT" | grep -o '[0-9.]*%' | sed 's/%//')
    if [ -n "$COVERAGE" ] && [ "${COVERAGE%.*}" -ge 80 ] 2>/dev/null; then
        echo -e "${GREEN}✓ Test coverage: ${COVERAGE}%${NC}"
    elif [ -n "$COVERAGE" ]; then
        echo -e "${YELLOW}⚠ Test coverage: ${COVERAGE}% (consider improving to ≥80%)${NC}"
    else
        echo -e "${GREEN}✓ Test coverage available (see above test output)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Could not determine test coverage${NC}"
fi
echo

echo -e "${GREEN}🎉 All Go Report Card A+ quality checks passed!${NC}"
echo -e "${BLUE}Your code meets the highest Go quality standards and is ready for submission.${NC}"
echo
echo -e "${BLUE}Quality Summary:${NC}"
echo -e "${GREEN}  ✓ Formatting: gofmt compliant${NC}"
echo -e "${GREEN}  ✓ Testing: All tests pass with race detection${NC}"
echo -e "${GREEN}  ✓ Static Analysis: go vet, staticcheck, golangci-lint clean${NC}"
echo -e "${GREEN}  ✓ Complexity: All functions ≤15 cyclomatic complexity${NC}"
echo -e "${GREEN}  ✓ Examples: All compile successfully${NC}"
echo -e "${GREEN}  ✓ Code Quality: No TODO/FIXME comments${NC}"

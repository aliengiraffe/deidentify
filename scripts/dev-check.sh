#!/bin/bash

# Development check script
# Runs all the checks that should pass before submitting a PR

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Running development checks...${NC}"
echo

# Check if gofmt is needed
echo -e "${YELLOW}Checking Go formatting...${NC}"
GOFMT_FILES=$(gofmt -l .)
if [ -n "$GOFMT_FILES" ]; then
    echo -e "${RED}✗ The following files need formatting:${NC}"
    echo "$GOFMT_FILES"
    echo -e "${YELLOW}Run 'gofmt -w .' to fix${NC}"
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

echo -e "${GREEN}🎉 All development checks passed!${NC}"
echo -e "${BLUE}Your code is ready for submission.${NC}"
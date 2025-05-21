#!/bin/bash

# Setup script for git pre-commit hook
# This script installs a pre-commit hook that automatically runs gofmt on staged Go files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up git pre-commit hook for Go formatting...${NC}"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo -e "${RED}Error: Not in a git repository root. Please run this script from the project root.${NC}"
    exit 1
fi

# Check if gofmt is available
if ! command -v gofmt &> /dev/null; then
    echo -e "${RED}Error: gofmt not found. Please install Go first.${NC}"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Check if pre-commit hook already exists
if [ -f ".git/hooks/pre-commit" ]; then
    echo -e "${YELLOW}Warning: pre-commit hook already exists.${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Setup cancelled.${NC}"
        exit 0
    fi
fi

# Create the pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash

# Git pre-commit hook to run gofmt on staged Go files
# This ensures all committed Go code is properly formatted

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get list of staged Go files
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$')

if [ -z "$STAGED_GO_FILES" ]; then
    # No Go files staged, allow commit
    exit 0
fi

echo -e "${YELLOW}Running gofmt on staged Go files...${NC}"

# Track if any files were modified
MODIFIED=false

for file in $STAGED_GO_FILES; do
    # Check if file exists (it might have been deleted)
    if [ ! -f "$file" ]; then
        continue
    fi
    
    # Run gofmt and capture the output
    FORMATTED_CONTENT=$(gofmt "$file")
    ORIGINAL_CONTENT=$(cat "$file")
    
    # Compare original and formatted content
    if [ "$FORMATTED_CONTENT" != "$ORIGINAL_CONTENT" ]; then
        echo -e "${YELLOW}Formatting $file${NC}"
        
        # Apply gofmt to the file
        gofmt -w -s "$file"
        
        # Add the formatted file back to staging
        git add "$file"
        
        MODIFIED=true
    fi
done

if [ "$MODIFIED" = true ]; then
    echo -e "${GREEN}✓ Go files have been formatted and re-staged${NC}"
    echo -e "${YELLOW}Please review the formatting changes and commit again${NC}"
    exit 1  # Prevent the commit so user can review changes
else
    echo -e "${GREEN}✓ All staged Go files are properly formatted${NC}"
    exit 0  # Allow the commit
fi
EOF

# Make the hook executable
chmod +x .git/hooks/pre-commit

echo -e "${GREEN}✓ Pre-commit hook installed successfully!${NC}"
echo
echo -e "${BLUE}The hook will now automatically:${NC}"
echo "  • Run gofmt on all staged Go files before each commit"
echo "  • Apply formatting and re-stage files if needed"
echo "  • Prevent commits with formatting issues until reviewed"
echo
echo -e "${YELLOW}Test the hook by staging a Go file and committing.${NC}"

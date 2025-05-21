# Contributing to Deidentify

Thank you for your interest in contributing to the Deidentify project! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- **Go**: Version 1.19 or later
- **Git**: For version control
- **gofmt**: Included with Go installation

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/yourusername/deidentify.git
   cd deidentify
   ```
3. Add the original repository as upstream:
   ```bash
   git remote add upstream https://github.com/aliengiraffe/deidentify.git
   ```

## Development Setup

### 1. Install Dependencies

```bash
go mod download
```

### 2. Set Up Pre-commit Hook

We use a pre-commit hook to ensure all Go code is properly formatted. Run the setup script:

```bash
./scripts/setup-pre-commit-hook.sh
```

This will:
- Install a git pre-commit hook that runs `gofmt` on staged Go files
- Automatically format code before commits
- Prevent commits with formatting issues

**Alternative manual setup:**
If you prefer to set it up manually, copy the pre-commit hook:
```bash
cp scripts/setup-pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### 3. Verify Setup

Test that everything is working:

```bash
# Run tests
go test ./...

# Run examples
go run examples/basic/main.go
go run examples/table/main.go  
go run examples/slices/main.go
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Write your code following our [Code Standards](#code-standards)
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run comprehensive development checks
./scripts/dev-check.sh

# Or run individual checks:
go test ./...                    # Run tests
go test -v ./...                 # Verbose test output
go test -race ./...              # Test with race detector
go test -bench=. ./...           # Run benchmarks
go vet ./...                     # Static analysis
```

### 4. Commit Changes

The pre-commit hook will automatically format your code:

```bash
git add .
git commit -m "Add new feature: description"
```

If the hook formats files, review the changes and commit again:
```bash
git commit -m "Add new feature: description"
```

## Code Standards

### Go Style Guidelines

- **Formatting**: All code must be formatted with `gofmt` (enforced by pre-commit hook)
- **Naming**: Follow Go naming conventions
  - Use `CamelCase` for exported functions/types
  - Use `camelCase` for internal functions/variables
  - Use descriptive names
  - **Package naming**: Don't include package name in function names (e.g., use `Text()` not `DeidentifyText()`)
- **Documentation**: 
  - All exported functions must have documentation comments
  - Start comments with the function name
  - Provide usage examples for complex functions

### Code Structure

- **Error Handling**: Use Go's standard error patterns
  - Return errors rather than panicking
  - Provide descriptive error messages
  - Wrap errors with context when appropriate

- **Testing**: 
  - Write table-driven tests where appropriate
  - Use descriptive test names
  - Test both success and error cases
  - Add benchmarks for performance-critical code

### Example Code Pattern

```go
// Example demonstrates proper function documentation
// and error handling patterns used in this project.
func (d *Deidentifier) Example(input string) (string, error) {
    if input == "" {
        return "", nil
    }
    
    result, err := d.processInput(input)
    if err != nil {
        return "", fmt.Errorf("failed to process input: %w", err)  
    }
    
    return result, nil
}
```

## Testing

### Test Structure

```bash
# Run all tests
go test ./...

# Run specific test
go test -run TestDeidentifySlices

# Run tests with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Test Guidelines

- **Unit Tests**: Test individual functions in isolation
- **Integration Tests**: Test complete workflows
- **Benchmarks**: Include benchmarks for performance-critical functions
- **Examples**: Add `Example` functions for documentation

### Adding New Tests

When adding new functionality:

1. **Write tests first** (TDD approach recommended)
2. **Test edge cases**: empty inputs, nil values, invalid data
3. **Test error conditions**: ensure errors are properly returned
4. **Add benchmarks**: for any performance-sensitive code

## Submitting Changes

### 1. Sync with Upstream

Before submitting, ensure your branch is up to date:

```bash
git fetch upstream
git rebase upstream/main
```

### 2. Create Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request on GitHub with:
   - **Clear title**: Summarize the change in 50 characters or less
   - **Description**: Explain what changes were made and why
   - **Testing**: Describe how the changes were tested
   - **Breaking changes**: Note any breaking changes

### 3. Pull Request Template

```markdown
## Summary
Brief description of changes

## Changes Made
- List specific changes
- Include any new functions/types added
- Note any removed or modified functionality

## Testing
- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] Examples updated (if applicable)
- [ ] Benchmarks added (if applicable)

## Breaking Changes
List any breaking changes and migration steps

## Related Issues
Closes #123
```

### 4. Code Review Process

- **All PRs require review** before merging
- **Address feedback promptly** and update your branch
- **Keep PRs focused** - one feature/fix per PR
- **Squash commits** if requested during review

## Release Process

Releases are automated via GitHub Actions when tags are pushed:

```bash
# Create and push a tag
git tag v1.x.x
git push origin v1.x.x
```

The automation will:
- Run all tests
- Create a GitHub release
- Generate changelog
- Publish to Go module proxy

## Development Scripts

The `scripts/` directory contains helpful development tools:

- **`setup-pre-commit-hook.sh`**: Sets up the gofmt pre-commit hook
- **`dev-check.sh`**: Runs all development checks (formatting, tests, build, examples)

### Running Development Checks

Before submitting a PR, run the comprehensive check script:

```bash
./scripts/dev-check.sh
```

This will verify:
- ✅ Go code formatting (`gofmt`)
- ✅ All tests pass
- ✅ No race conditions (`go test -race`)
- ✅ Code builds successfully
- ✅ No issues found by `go vet`
- ✅ All examples compile with recent changes
- ⚠️  Check for TODO/FIXME comments (warning only)

## Getting Help

- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check examples and README.md

## Project Structure

```
deidentify/
├── deidentify.go           # Main implementation
├── deidentify_test.go      # Main tests
├── patterns.go             # Regex patterns for PII detection
├── data.go                 # Sample data for generation
├── examples/               # Usage examples
│   ├── basic/              # Simple text deidentification
│   ├── table/              # Structured data processing
│   ├── slices/             # Slice data processing
│   └── international/      # International address support
├── scripts/                # Development scripts
│   └── setup-pre-commit-hook.sh
├── CONTRIBUTING.md         # This file
├── README.md               # Project documentation
└── CLAUDE.md               # AI context and guidelines
```

## Tips for Contributors

1. **Start small**: Begin with documentation fixes or small features
2. **Ask questions**: Create an issue to discuss large changes before implementing
3. **Test thoroughly**: Run all tests and examples before submitting
4. **Follow conventions**: Match the existing code style and patterns
5. **Be patient**: Code review and feedback are part of the process

Thank you for contributing to Deidentify!
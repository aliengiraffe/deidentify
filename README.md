# Deidentify

![Version](https://img.shields.io/github/v/release/aliengiraffe/deidentify.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/aliengiraffe/deidentify?1=2)](https://goreportcard.com/report/github.com/aliengiraffe/deidentify)
[![GoDoc](https://godoc.org/github.com/aliengiraffe/deidentify?status.svg)](https://godoc.org/github.com/aliengiraffe/deidentify)
[![License](https://img.shields.io/github/license/aliengiraffe/deidentify.svg?1=1)](LICENSE)

![Release](https://github.com/aliengiraffe/deidentify/actions/workflows/release.yml/badge.svg)

A Go library for detecting and removing personally identifiable information (PII) from text and structured data.

## Overview

`deidentify` is an open source Go package created by AlienGiraffe, Inc. that provides simple yet powerful tools for identifying and anonymizing personal information in various formats. It preserves data utility while protecting privacy through consistent, deterministic replacements.

## Features

- **Multiple PII types support**: Emails, phone numbers, SSNs, credit cards, names, and addresses
- **Format preservation**: Maintains the original data format for better usability  
- **Deterministic replacements**: Same inputs produce the same outputs for referential integrity
- **Context awareness**: Uses column names as context to prevent correlation
- **Table processing**: Handles structured data with type-aware deidentification
- **Thread-safe**: Suitable for concurrent processing

## Installation

```bash
go get github.com/aliengiraffe/deidentify
```

## Usage

### Basic Example

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/aliengiraffe/deidentify"
)

func main() {
    // Generate a secure secret key (or provide your own)
    secretKey, err := deidentify.GenerateSecretKey()
    if err != nil {
        log.Fatal("Failed to generate secret key:", err)
    }
    
    // Create a deidentifier instance
    d := deidentify.NewDeidentifier(secretKey)
    
    // Deidentify text containing PII
    text := `Contact Frodo Baggins at frodo.baggins@shire.me or (555) 123-4567.
His SSN is 123-45-6789 and he lives at 1 Bagshot Row, Hobbiton.`

    redacted, err := d.Text(text)
    if err != nil {
        log.Fatal("Failed to deidentify text:", err)
    }
    
    fmt.Println(redacted)
    // Output example:
    // Contact Taylor Miller at member4921@demo.co or (555) 642-8317.
    // His SSN is 304-51-9872 and he lives at 2845 Oak Ave.
}
```

### Processing Structured Data

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/aliengiraffe/deidentify"
)

func main() {
    secretKey, err := deidentify.GenerateSecretKey()
    if err != nil {
        log.Fatal("Failed to generate secret key:", err)
    }
    
    d := deidentify.NewDeidentifier(secretKey)
    
    // Create a table with PII data
    table := &deidentify.Table{
        Columns: []deidentify.Column{
            {
                Name:     "customer_name",
                DataType: deidentify.TypeName,
                Values:   []interface{}{"Gandalf Grey", "Aragorn Strider", nil},
            },
            {
                Name:     "email",
                DataType: deidentify.TypeEmail,
                Values:   []interface{}{"mithrandir@wizard.com", "ranger@gondor.me", ""},
            },
        },
    }
    
    // Deidentify the table
    result, err := d.Table(table)
    if err != nil {
        log.Fatal("Failed to deidentify table:", err)
    }
    
    // Process the result
    for i, col := range result.Columns {
        fmt.Printf("Column: %s\n", col.Name)
        for j, val := range col.Values {
            fmt.Printf("  [%d]: %v\n", j, val)
        }
    }
}
```

### Processing Slice Data

```go
// Deidentify [][]string data (CSV-like format)
data := [][]string{
    {"Alice Johnson", "alice@example.com", "555-123-4567"},
    {"Bob Smith", "bob@company.org", "(555) 987-6543"},
}

// Option 1: Automatic type inference (recommended)
result, err := d.Slices(data)
if err != nil {
    log.Fatal("Failed to deidentify:", err)
}
// Types are automatically detected: Name, Email, Phone
// Result: [["Taylor Miller", "user4921@demo.co", "555-642-8317"], ...]

// Option 2: Explicit column types only
columnTypes := []deidentify.DataType{deidentify.TypeName, deidentify.TypeEmail, deidentify.TypePhone}
result, err = d.Slices(data, columnTypes)

// Option 3: Both explicit types and custom column names
columnNames := []string{"customer_name", "customer_email", "customer_phone"}
result, err = d.Slices(data, columnTypes, columnNames)
```

## More Examples

See the [examples](./examples) directory for comprehensive usage patterns:

- [Basic usage](./examples/basic/main.go): Simple text deidentification
- [Table processing](./examples/table/main.go): Structured data with multiple columns and types  
- [Slice processing](./examples/slices/main.go): CSV-like data processing with [][]string
- [International address handling](./examples/international/main.go): Support for addresses across different regions

## Configuration

The `deidentify` package uses a deterministic approach for consistency. The secret key provides the randomness source, making the anonymization both reproducible and secure.

## Supported PII Types

| PII Type     | Description                 | Example Input                | Example Output            |
|--------------|-----------------------------|-----------------------------|---------------------------|
| TypeName     | Personal names              | Bilbo Baggins               | Taylor Miller             |
| TypeEmail    | Email addresses             | bilbo@bag-end.shire         | user4921@demo.co          |
| TypePhone    | Phone numbers               | (555) 123-4567              | (555) 642-8317            |
| TypeSSN      | Social Security Numbers     | 123-45-6789                 | 304-51-9872               |
| TypeCreditCard| Credit card numbers        | 4111-1111-1111-1111         | 4000 8521 7694 3217       |
| TypeAddress  | Street addresses            | Bag End, Bagshot Row        | 2845 Oak Ave              |

## Security

While this library aims to detect common PII patterns, no automated system can guarantee 100% detection. Always verify the results in sensitive applications.

Note: By default, the library preserves area codes in phone numbers for better usability, as they often indicate geographic regions rather than individuals. Consider your specific requirements when implementing.

## Data Variety

The library provides rich anonymization with:

- 110+ gender-neutral first names
- 130+ diverse last names
- 105+ fictional email domains
- 100+ email username patterns
- 120+ street name variations with international formats

This extensive variety of replacement options enhances privacy by increasing the anonymization space and reducing the likelihood of pattern recognition.

## International Support

The library includes support for international address formats:

- North American: US and Canadian style addresses
- European: UK, French, German, Italian, Spanish, etc.
- Asian: Japanese, Chinese, Southeast Asian formats
- Middle Eastern and global formats

The detection patterns have been optimized to recognize common address structures across different languages and regional conventions, while the anonymization preserves format and readability.

## Releases

### Creating a New Release

The library uses GitHub Actions to automate the release process. To create a new release:

1. Update your code and commit all changes
2. Create and push a new tag with semantic versioning format:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. The GitHub Actions workflow will automatically:
   - Run tests to ensure everything works
   - Generate a changelog based on commits since the last tag
   - Create a GitHub release with documentation
   - Publish the new version to the Go module proxy

This makes the new version immediately available for users to install via `go get github.com/aliengiraffe/deidentify@v1.0.0`.

## Performance

To run performance benchmarks:

```bash
# Run all benchmarks
go test -bench=. -benchtime=10s

# Run only the paragraph deidentification benchmark
go test -bench=BenchmarkParagraphDeidentification -benchtime=1x

# Run benchmarks with memory allocation stats
go test -bench=. -benchmem

# Run parallel benchmarks to test concurrent performance
go test -bench=BenchmarkParagraphDeidentificationParallel
```

### CPU and Memory Profiling with pprof

For detailed performance analysis, you can use [pprof](https://github.com/google/pprof) to profile CPU usage and memory allocations:

```bash
# Generate CPU profile
go test -bench=BenchmarkParagraphDeidentification -cpuprofile=cpu.prof -benchtime=10s

# Generate memory profile
go test -bench=BenchmarkParagraphDeidentification -memprofile=mem.prof -benchtime=10s

# Analyze CPU profile in terminal
go tool pprof cpu.prof
# Then use interactive commands like 'top', 'list', 'web'

# Analyze memory profile in terminal
go tool pprof mem.prof
```

#### Interactive Web UI

The most powerful way to analyze profiles is using pprof's built-in web server, which provides an interactive visualization:

```bash
# Start interactive web UI for CPU profile (opens browser automatically)
go tool pprof -http=:8080 cpu.prof

# Start interactive web UI for memory profile on different port
go tool pprof -http=:8081 mem.prof

# If browser doesn't open automatically, navigate to:
# http://localhost:8080 (for CPU)
# http://localhost:8081 (for memory)
```

The web UI provides:
- **Flame Graph**: Interactive flame graph showing call stack and CPU/memory usage
- **Graph View**: Call graph with edges showing relationships and costs
- **Top View**: Sorted list of functions by resource consumption
- **Source View**: Line-by-line annotation of source code with costs
- **Peek View**: Shows callers and callees of selected functions
- **Disassembly View**: Assembly-level analysis

#### Advanced Analysis

```bash
# Focus on specific functions (e.g., deidentify package)
go tool pprof -focus=deidentify cpu.prof

# Compare two profiles (e.g., before and after optimization)
go tool pprof -base=cpu_before.prof cpu_after.prof

# Generate a PDF report (requires graphviz)
go tool pprof -pdf cpu.prof > cpu_profile.pdf

# Filter by specific time range or samples
go tool pprof -show_from=Text -show=deidentify cpu.prof
```

#### Automated Profiling

For convenience, use the included profiling script:

```bash
./scripts/profile-benchmarks.sh
```

This script will:
- Run benchmarks with CPU and memory profiling
- Generate text reports (top consumers, full profiles)
- Create visual graphs (SVG/PNG) if graphviz is installed
- Save all artifacts in the `profiles/` directory

#### CI/CD Integration

Pull requests automatically generate profiling reports through GitHub Actions. The workflow:
- Runs benchmarks with CPU and memory profiling
- Generates pprof reports and visualizations
- Posts a summary comment on the PR with key metrics
- Uploads full profiling artifacts for download

The benchmarks measure the time to deidentify paragraphs containing various types of PII. On modern hardware, the library can process over 600 paragraphs per second with an average processing time of ~1.5ms per paragraph.

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for detailed information on how to contribute to this project.

**Quick start for contributors:**

1. Fork the repository and clone your fork
2. Set up the development environment:
   ```bash
   ./scripts/setup-pre-commit-hook.sh
   go mod download
   ```
3. Create your feature branch (`git checkout -b feature/amazing-feature`)
4. Make your changes and ensure tests pass (`go test ./...`)
5. Commit your changes (pre-commit hook will format code automatically)
6. Push to your fork and submit a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on code standards, testing, and the development workflow.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## About

Created and maintained by [AlienGiraffe, Inc.](https://github.com/aliengiraffe)

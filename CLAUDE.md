# Deidentify

A Go library for removing personally identifiable information (PII) from text data.

## Project Structure

This project follows standard Go package conventions:

```
deidentify/
├── doc.go              # Package documentation
├── deidentify.go       # Main package implementation
├── data.go             # Replacement value tables (names, domains, streets)
├── patterns.go         # Regular expressions used for PII detection
├── deidentify_test.go  # Package tests
├── example_test.go     # Runnable godoc examples
├── benchmark_test.go   # Performance benchmarks
├── examples/           # Example programs
│   ├── basic/          # Simple text deidentification
│   ├── table/          # Table-based deidentification
│   ├── slices/         # CSV-like [][]string deidentification
│   └── international/  # International address handling
└── go.mod              # Module definition
```

## Usage

The package provides functions to detect and redact PII from text. It can be imported and used in your Go applications:

```go
import "github.com/aliengiraffe/deidentify"
```

See the [examples](./examples) directory for detailed usage patterns.

## Design Principles

This package follows Go's design philosophy:

1. **Simplicity**: The API is designed to be simple and intuitive
2. **Composability**: Functions can be combined to create custom deidentification pipelines
3. **Efficiency**: Optimized for performance with minimal allocations
4. **Error handling**: Uses Go's standard error patterns for robust error reporting

## API Overview

The package exposes types and functions following Go's idiomatic practices:

### Core Types

- `Deidentifier`: Replaces PII with deterministic, format-preserving substitutes. Safe for concurrent use.
- `DataType`: The kind of PII a value holds (`TypeName`, `TypeEmail`, `TypePhone`, `TypeSSN`, `TypeCreditCard`, `TypeAddress`, `TypeGeneric`)
- `Table` / `Column`: Column-oriented data to deidentify as a unit

### Constructors

- `GenerateSecretKey() (string, error)`: Returns a hex-encoded 256-bit random key
- `NewDeidentifier(secretKey string) *Deidentifier`: Creates a deidentifier bound to a secret key

### Main Methods

- `Text(text string) (string, error)`: Finds and replaces PII in free-form text
- `Table(table *Table) (*Table, error)`: Deidentifies column-oriented data by declared type
- `Slices(data [][]string, optional ...interface{}) ([][]string, error)`: Deidentifies CSV-like data, inferring column types when not supplied

### Single-value Methods

`Name`, `Email`, `Phone`, `SSN`, `CreditCard`, and `Address` each deidentify one
value of a known type, returning `(string, error)`. `ClearMappings()` discards
the accumulated mapping tables.

Replacements are deterministic: the same input and secret key always produce the
same output, which preserves referential integrity across records and runs.

## Development Guidelines

When contributing to this project, follow these practices:

1. Use `gofmt` to format all code
2. Write tests for all new functionality
3. Follow [Effective Go](https://go.dev/doc/effective_go) guidelines:
   - Meaningful variable names
   - Proper error handling with descriptive error messages
   - Concise documentation with examples
   - Implementation of standard interfaces where appropriate

4. Use idiomatic Go patterns:
   - Return errors rather than using `panic`
   - Use composition over inheritance
   - Make zero values useful

## Testing

Run the test suite with:

```
go test
```

For more verbose output:

```
go test -v
```

## Examples

The library includes multiple examples to demonstrate different usage patterns:

### Basic Example

Simple text deidentification of strings and specific PII types:

```
go run examples/basic/main.go
```

### Table Example

Comprehensive example for deidentifying structured data in tables:

```
go run examples/table/main.go
```

## License

[License details here]

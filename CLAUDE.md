# Deidentify

A Go library for removing personally identifiable information (PII) from text data.

## Project Structure

This project follows standard Go package conventions:

```
deidentify/
├── deidentify.go       # Main package implementation
├── deidentify_test.go  # Package tests
├── examples/           # Example usages
│   ├── basic/
│   │   └── main.go     # Simple text deidentification example
│   └── table/
│       └── main.go     # Table-based deidentification example
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

- `Deidentifier`: Interface for objects that can identify and redact PII
- `Option`: Functional options for configuring deidentification behavior

### Main Functions

- `New(options ...Option) *Deidentifier`: Creates a new deidentifier with specified options
- `Deidentify(text string) (string, error)`: Processes text, returning a deidentified version
- `DeidentifyBytes(data []byte) ([]byte, error)`: Processes byte data for binary-safe operations

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

# Deidentify

[![Go Report Card](https://goreportcard.com/badge/github.com/aliengiraffe/deidentify)](https://goreportcard.com/report/github.com/aliengiraffe/deidentify)
[![GoDoc](https://godoc.org/github.com/aliengiraffe/deidentify?status.svg)](https://godoc.org/github.com/aliengiraffe/deidentify)
[![License](https://img.shields.io/github/license/aliengiraffe/deidentify.svg)](LICENSE)

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

    redacted, err := d.DeidentifyText(text)
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
    result, err := d.DeidentifyTable(table)
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

## More Examples

See the [examples](./examples) directory for comprehensive usage patterns:

- [Basic usage](./examples/basic/main.go): Simple text deidentification
- [Table processing](./examples/table/main.go): Working with structured data

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## About

Created and maintained by [AlienGiraffe, Inc.](https://github.com/aliengiraffe)

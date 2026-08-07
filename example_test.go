package deidentify_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/aliengiraffe/deidentify"
)

// The examples below assert on stable properties rather than on the generated
// values themselves, because the exact replacement chosen for a given input
// depends on the secret key.

func ExampleNewDeidentifier() {
	// In production, generate a key once with GenerateSecretKey and store it.
	// Reusing the same key keeps replacements consistent across runs.
	d := deidentify.NewDeidentifier("example-secret-key")

	redacted, err := d.Text("Please email Frodo Baggins at frodo.baggins@shire.me or call (555) 123-4567.")
	if err != nil {
		log.Fatal(err)
	}

	// redacted reads, for example:
	// "Please email Marlo Cole at undefined6840@private.com or call (555) 777-3471."
	fmt.Println(strings.Contains(redacted, "Frodo Baggins"))
	fmt.Println(strings.Contains(redacted, "frodo.baggins@shire.me"))
	fmt.Println(strings.Contains(redacted, "(555) 123-4567"))
	// Output:
	// false
	// false
	// false
}

func ExampleGenerateSecretKey() {
	secretKey, err := deidentify.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}

	// The key is a hex-encoded 256-bit value.
	fmt.Println(len(secretKey))
	// Output: 64
}

func ExampleDeidentifier_Email() {
	d := deidentify.NewDeidentifier("example-secret-key")

	first, err := d.Email("bilbo@bag-end.shire")
	if err != nil {
		log.Fatal(err)
	}
	second, err := d.Email("bilbo@bag-end.shire")
	if err != nil {
		log.Fatal(err)
	}
	other, err := d.Email("frodo@shire.me")
	if err != nil {
		log.Fatal(err)
	}

	// The same address always maps to the same replacement, so records can
	// still be joined on the anonymized value.
	fmt.Println(first == second)
	fmt.Println(first == other)
	fmt.Println(strings.Contains(first, "@"))
	// Output:
	// true
	// false
	// true
}

func ExampleDeidentifier_Phone() {
	d := deidentify.NewDeidentifier("example-secret-key")

	redacted, err := d.Phone("(555) 123-4567")
	if err != nil {
		log.Fatal(err)
	}

	// Punctuation and area code are preserved; only the subscriber digits change.
	fmt.Println(strings.HasPrefix(redacted, "(555) "))
	fmt.Println(len(redacted) == len("(555) 123-4567"))
	fmt.Println(redacted == "(555) 123-4567")
	// Output:
	// true
	// true
	// false
}

func ExampleDeidentifier_Table() {
	d := deidentify.NewDeidentifier("example-secret-key")

	table := &deidentify.Table{
		Columns: []deidentify.Column{
			{
				Name:     "customer_name",
				DataType: deidentify.TypeName,
				Values:   []interface{}{"Gandalf Grey", nil},
			},
			{
				Name:     "email",
				DataType: deidentify.TypeEmail,
				Values:   []interface{}{"mithrandir@wizard.com", ""},
			},
		},
	}

	result, err := d.Table(table)
	if err != nil {
		log.Fatal(err)
	}

	// Nil and empty values pass through untouched.
	fmt.Println(result.Columns[0].Values[0] == "Gandalf Grey")
	fmt.Println(result.Columns[0].Values[1] == nil)
	fmt.Println(result.Columns[1].Values[1] == "")
	// Output:
	// false
	// true
	// true
}

func ExampleDeidentifier_Slices() {
	d := deidentify.NewDeidentifier("example-secret-key")

	data := [][]string{
		{"Gandalf Grey", "mithrandir@wizard.com", "555-123-4567"},
		{"Aragorn Strider", "ranger@gondor.me", "(555) 987-6543"},
	}

	// With no column types supplied, each column's type is inferred.
	result, err := d.Slices(data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(result), len(result[0]))
	fmt.Println(result[0][1] == "mithrandir@wizard.com")
	fmt.Println(strings.Contains(result[0][1], "@"))
	// Output:
	// 2 3
	// false
	// true
}

func ExampleDeidentifier_Slices_explicitTypes() {
	d := deidentify.NewDeidentifier("example-secret-key")

	data := [][]string{
		{"Gandalf Grey", "mithrandir@wizard.com"},
		{"Aragorn Strider", "ranger@gondor.me"},
	}

	// Supplying types skips inference; supplying names controls the context
	// used for replacement, so the same value in two columns differs.
	columnTypes := []deidentify.DataType{deidentify.TypeName, deidentify.TypeEmail}
	columnNames := []string{"customer_name", "customer_email"}

	result, err := d.Slices(data, columnTypes, columnNames)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result[0][0] == "Gandalf Grey")
	fmt.Println(len(result))
	// Output:
	// false
	// 2
}

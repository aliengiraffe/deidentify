/*
Package deidentify removes personally identifiable information (PII) from text
and structured data while preserving the shape and utility of the original data.

Replacements are deterministic: the same input, deidentified with the same
secret key, always yields the same output. This preserves referential integrity
across records and runs, so joins and groupings still work on anonymized data.
Different secret keys produce different outputs, so the mapping cannot be
reproduced without the key.

# Getting started

Create a Deidentifier with a secret key and call [Deidentifier.Text] to redact
free-form text:

	secretKey, err := deidentify.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}

	d := deidentify.NewDeidentifier(secretKey)

	redacted, err := d.Text("Contact Frodo Baggins at frodo@shire.me or (555) 123-4567.")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(redacted)

# Supported PII types

The package detects and replaces names, email addresses, phone numbers, Social
Security numbers, credit card numbers, and street addresses. Each has a
corresponding [DataType] constant and a convenience method on [Deidentifier]
for deidentifying a single value of a known type.

Replacements preserve the format of the original value. Phone numbers keep
their punctuation and area code, credit card numbers keep a valid Luhn
checksum, and SSNs keep a structurally valid area-group-serial layout.

# Structured data

[Deidentifier.Table] processes column-oriented data where the type of each
column is known, and [Deidentifier.Slices] processes CSV-like [][]string data,
inferring the type of each column when it is not supplied. Both use the column
name as part of the replacement context, so the same value appearing in two
different columns maps to two different replacements. This prevents correlation
across columns.

Values of type [TypeGeneric] are returned unchanged, which is how columns with
no detected PII pass through the pipeline intact.

# Concurrency

A [Deidentifier] is safe for concurrent use by multiple goroutines. Its
internal mapping tables are guarded by a mutex.

# Limitations

Detection is pattern-based. No automated system can guarantee that it finds
every piece of PII, particularly in unstructured text, so results should be
verified in sensitive applications. By default, phone area codes are preserved
because they usually indicate a geographic region rather than an individual;
consider whether that tradeoff suits your threat model.
*/
package deidentify

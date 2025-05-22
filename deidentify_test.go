package deidentify

import (
	"regexp"
	"strings"
	"testing"
)

func TestDeterministicReplacement(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	// Test same input produces same output
	original := "john.doe@company.com"
	result1 := d.generateEmail(original)
	result2 := d.generateEmail(original)

	if result1 != result2 {
		t.Errorf("Expected deterministic output, got %s and %s", result1, result2)
	}

	// Test different secret keys produce different outputs
	d2 := NewDeidentifier("different-secret-key")
	result3 := d2.generateEmail(original)

	if result1 == result3 {
		t.Error("Different secret keys should produce different outputs")
	}
}

func TestEmailDeidentification(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	testCases := []string{
		"john.doe@company.com",
		"admin@example.org",
		"user123@test.co.uk",
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9]+\d+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	for _, original := range testCases {
		result := d.generateEmail(original)

		if !emailRegex.MatchString(result) {
			t.Errorf("Generated email %s doesn't match valid format", result)
		}

		if result == original {
			t.Errorf("Email should be anonymized, got same value: %s", result)
		}
	}
}

func TestPhoneDeidentification(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	testCases := []struct {
		original string
		pattern  string
	}{
		{"+1 (555) 123-4567", `^\+1 \(555\) \d{3}-\d{4}$`},
		{"555-123-4567", `^555-\d{3}-\d{4}$`},
		{"(555) 123 4567", `^\(555\) \d{3} \d{4}$`},
		{"555.123.4567", `^555\.\d{3}\.\d{4}$`},
	}

	for _, tc := range testCases {
		result := d.generatePhone(tc.original)
		matched, _ := regexp.MatchString(tc.pattern, result)

		if !matched {
			t.Errorf("Phone %s doesn't match expected pattern %s, got %s",
				tc.original, tc.pattern, result)
		}

		if result == tc.original {
			t.Errorf("Phone should be anonymized, got same value: %s", result)
		}
	}
}

func TestSSNDeidentification(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	testCases := []string{
		"123-45-6789",
		"987-65-4321",
		"555-12-3456",
		"123 45 6789", // With spaces
		"123456789",   // Without separators
	}

	ssnRegex := regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`)

	for _, original := range testCases {
		result := d.generateSSN(original)

		if !ssnRegex.MatchString(result) {
			t.Errorf("Generated SSN %s doesn't match valid format", result)
		}

		// Check it's not an invalid SSN pattern
		if strings.HasPrefix(result, "666-") || strings.HasPrefix(result, "900-") {
			t.Errorf("Generated invalid SSN pattern: %s", result)
		}

		if result == original {
			t.Errorf("SSN should be anonymized, got same value: %s", result)
		}
	}
}

func TestSSNPatternMatching(t *testing.T) {
	// Test that our SSN regex pattern matches all expected formats
	pattern := regexp.MustCompile(`^\d{3}[- ]?\d{2}[- ]?\d{4}$`)

	testCases := []struct {
		input    string
		expected bool
	}{
		{"123-45-6789", true},  // Hyphenated format
		{"123 45 6789", true},  // Space-separated format
		{"123456789", true},    // No separators
		{"12345678", false},    // Too short
		{"1234567890", false},  // Too long
		{"12A-45-6789", false}, // Contains non-digit
		{"123-456-789", false}, // Wrong grouping with hyphens
		{"123 456 789", false}, // Wrong grouping with spaces
	}

	for _, tc := range testCases {
		matched := pattern.MatchString(tc.input)
		if matched != tc.expected {
			t.Errorf("SSN pattern matching for %s: expected %v, got %v",
				tc.input, tc.expected, matched)
		}
	}
}

func TestCreditCardDeidentification(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	testCases := []string{
		"4532-1234-5678-9012",
		"4000 1234 5678 9010",
		"4111111111111111",
	}

	for _, original := range testCases {
		result := d.generateCreditCard(original)

		// Remove spaces and check Luhn
		cleanResult := strings.ReplaceAll(result, " ", "")
		if !isValidLuhn(cleanResult) {
			t.Errorf("Generated credit card %s has invalid Luhn checksum", result)
		}

		// Should start with test card prefix
		if !strings.HasPrefix(cleanResult, "4000") {
			t.Errorf("Generated credit card should start with test prefix 4000, got %s", result)
		}

		if result == original {
			t.Errorf("Credit card should be anonymized, got same value: %s", result)
		}
	}
}

func TestTableDeidentification(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	table := &Table{
		Columns: []Column{
			{
				Name:     "name",
				DataType: TypeName,
				Values:   []interface{}{"John Doe", "Jane Smith", "Bob Johnson"},
			},
			{
				Name:     "email",
				DataType: TypeEmail,
				Values:   []interface{}{"john@company.com", "jane@company.com", "bob@company.com"},
			},
			{
				Name:     "phone",
				DataType: TypePhone,
				Values:   []interface{}{"(555) 123-4567", "(555) 987-6543", nil},
			},
		},
	}

	result, err := d.Table(table)
	if err != nil {
		t.Fatalf("Error deidentifying table: %v", err)
	}

	if len(result.Columns) != len(table.Columns) {
		t.Error("Result should have same number of columns")
	}

	// Check that values are different but format is preserved
	for i, col := range result.Columns {
		originalCol := table.Columns[i]

		if len(col.Values) != len(originalCol.Values) {
			t.Errorf("Column %s should have same number of values", col.Name)
		}

		for j, val := range col.Values {
			originalVal := originalCol.Values[j]

			// Nil values should remain nil
			if originalVal == nil {
				if val != nil {
					t.Errorf("Nil values should remain nil in column %s, row %d", col.Name, j)
				}
				continue
			}

			// Non-nil values should be changed
			if val == originalVal {
				t.Errorf("Value should be anonymized in column %s, row %d: %v", col.Name, j, val)
			}
		}
	}
}

func TestReferentialIntegrity(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	// Same value within same column should map to same result
	email1, _ := d.deidentifyValue("test@company.com", TypeEmail, "email")
	email2, _ := d.deidentifyValue("test@company.com", TypeEmail, "email")

	if email1 != email2 {
		t.Error("Same input should produce same output for referential integrity")
	}

	// We could test column-based context with different tables:
	/*
		// Test with table processing
		table1 := &Table{
			Columns: []Column{
				{Name: "primary_email", DataType: TypeEmail, Values: []interface{}{"user@test.com"}},
			},
		}

		table2 := &Table{
			Columns: []Column{
				{Name: "backup_email", DataType: TypeEmail, Values: []interface{}{"user@test.com"}},
			},
		}

		result1, _ := d.Table(table1)
		result2, _ := d.Table(table2)

		val1 := result1.Columns[0].Values[0]
		val2 := result2.Columns[0].Values[0]

		if val1 == val2 {
			t.Error("Different column names should produce different mappings")
		}
	*/

}

func TestSecretKeyGeneration(t *testing.T) {
	key1, err1 := GenerateSecretKey()
	key2, err2 := GenerateSecretKey()

	if err1 != nil || err2 != nil {
		t.Fatal("Error generating secret keys")
	}

	if key1 == key2 {
		t.Error("Generated keys should be different")
	}

	if len(key1) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Expected key length 64, got %d", len(key1))
	}
}

func TestText(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	testCases := []struct {
		name     string
		input    string
		patterns []string // Patterns to verify in the output
	}{
		{
			name:     "Empty input",
			input:    "",
			patterns: []string{},
		},
		{
			name:  "Email detection",
			input: "Contact me at john.doe@example.com for more information",
			patterns: []string{
				`Contact me at .+@.+ for more information`,
			},
		},
		{
			name:  "Phone detection",
			input: "Call me at (555) 123-4567 or 555-987-6543",
			patterns: []string{
				`Call me at \(555\) \d{3}-\d{4} or 555-\d{3}-\d{4}`,
			},
		},
		{
			name:  "SSN detection with hyphens",
			input: "My SSN is 123-45-6789 and my friend's is 987654321",
			patterns: []string{
				`My SSN is \d{3}-\d{2}-\d{4} and my friend's is \d{3}-\d{2}-\d{4}`,
			},
		},
		{
			name:  "SSN detection with spaces",
			input: "My social security number is 123 45 6789",
			patterns: []string{
				`My social security number is \d{3}-\d{2}-\d{4}`,
			},
		},
		{
			name:  "SSN detection without separators",
			input: "Customer SSN: 123456789",
			patterns: []string{
				`Customer SSN: \d{3}-\d{2}-\d{4}`,
			},
		},
		{
			name:  "Multiple PII types",
			input: "John Smith (john.smith@example.com) lives at 123 Oak Avenue.",
			patterns: []string{
				`.+ \(.+@.+\) lives at \d+ .+\.`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := d.Text(tc.input)
			if err != nil {
				t.Fatalf("Text() error = %v", err)
			}

			// For empty input, check that output is empty
			if tc.input == "" {
				if result != "" {
					t.Errorf("Text() didn't return empty string for empty input, got %q", result)
				}
				return
			}

			// Result should be different from input if input contains PII
			if result == tc.input && len(tc.patterns) > 0 {
				t.Errorf("Text() returned unchanged text: %s", result)
			}

			// Check that the result matches expected patterns
			for _, pattern := range tc.patterns {
				matched, err := regexp.MatchString(pattern, result)
				if err != nil {
					t.Fatalf("Failed to match pattern: %v", err)
				}
				if !matched {
					t.Errorf("Text() result doesn't match pattern\nPattern: %s\nResult:  %s", pattern, result)
				}
			}
		})
	}
}

func TestConvenienceMethods(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	// Test Email
	email := "test@example.com"
	emailResult, err := d.Email(email)
	if err != nil {
		t.Fatalf("Email failed: %v", err)
	}
	if emailResult == email {
		t.Errorf("Email should produce different result, got: %s", emailResult)
	}
	if !strings.Contains(emailResult, "@") {
		t.Errorf("Email result doesn't look like an email: %s", emailResult)
	}

	// Test Phone
	phone := "(555) 123-4567"
	phoneResult, err := d.Phone(phone)
	if err != nil {
		t.Fatalf("Phone failed: %v", err)
	}
	if phoneResult == phone {
		t.Errorf("Phone should produce different result, got: %s", phoneResult)
	}

	// Test SSN
	ssn := "123-45-6789"
	ssnResult, err := d.SSN(ssn)
	if err != nil {
		t.Fatalf("SSN failed: %v", err)
	}
	if ssnResult == ssn {
		t.Errorf("SSN should produce different result, got: %s", ssnResult)
	}
	if !regexp.MustCompile(`\d{3}-\d{2}-\d{4}`).MatchString(ssnResult) {
		t.Errorf("SSN result doesn't match SSN format: %s", ssnResult)
	}
}

// Helper function to validate Luhn checksum
func isValidLuhn(cardNumber string) bool {
	sum := 0
	alternate := false

	for i := len(cardNumber) - 1; i >= 0; i-- {
		digit := int(cardNumber[i] - '0')

		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

func BenchmarkEmailGeneration(b *testing.B) {
	d := NewDeidentifier("benchmark-key")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.generateEmail("test@example.com")
	}
}

func BenchmarkTableDeidentification(b *testing.B) {
	d := NewDeidentifier("benchmark-key")

	table := &Table{
		Columns: []Column{
			{Name: "name", DataType: TypeName, Values: make([]interface{}, 1000)},
			{Name: "email", DataType: TypeEmail, Values: make([]interface{}, 1000)},
		},
	}

	// Fill with test data
	for i := 0; i < 1000; i++ {
		table.Columns[0].Values[i] = "John Doe"
		table.Columns[1].Values[i] = "john@company.com"
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.Table(table)
		if err != nil {
			b.Fatalf("Table failed: %v", err)
		}
	}
}

func BenchmarkTextDeidentification(b *testing.B) {
	d := NewDeidentifier("benchmark-key")

	text := `Contact John Smith at john.smith@example.com or (555) 123-4567.
His SSN is 123-45-6789 and he lives at 123 Main Street in New York.
Please process his payment using credit card 4111-1111-1111-1111.`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.Text(text)
		if err != nil {
			b.Fatalf("Text failed: %v", err)
		}
	}
}

func TestSlices(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	// Test data as [][]string
	data := [][]string{
		{"John Doe", "john.doe@example.com", "555-123-4567", "123-45-6789"},
		{"Jane Smith", "jane.smith@company.org", "(555) 987-6543", "987-65-4321"},
		{"Bob Johnson", "bob@test.co.uk", "555.111.2222", "456-78-9012"},
		{"", "", "", ""}, // Test empty values
	}

	columnTypes := []DataType{TypeName, TypeEmail, TypePhone, TypeSSN}
	columnNames := []string{"name", "email", "phone", "ssn"}

	// Test successful deidentification
	result, err := d.Slices(data, columnTypes, columnNames)
	if err != nil {
		t.Fatalf("Slices failed: %v", err)
	}

	// Check result dimensions
	checkSlicesDimensions(t, result, data)

	// Test that non-empty values are deidentified
	checkNonEmptyValuesDeidentified(t, result, data)

	// Test that empty values remain empty
	checkEmptyValuesRemainEmpty(t, result)

	// Test deterministic behavior
	checkDeterministicBehavior(t, d, data, columnTypes, columnNames, result)

	// Test with different column names (should produce different results)
	checkDifferentColumnNames(t, data, columnTypes, result)
}

func checkSlicesDimensions(t *testing.T, result, data [][]string) {
	if len(result) != len(data) {
		t.Errorf("Expected %d rows, got %d", len(data), len(result))
	}

	for i, row := range result {
		if len(row) != len(data[i]) {
			t.Errorf("Row %d: expected %d columns, got %d", i, len(data[i]), len(row))
		}
	}
}

func checkNonEmptyValuesDeidentified(t *testing.T, result, data [][]string) {
	if result[0][0] == data[0][0] && data[0][0] != "" {
		t.Error("Name should be deidentified")
	}
	if result[0][1] == data[0][1] && data[0][1] != "" {
		t.Error("Email should be deidentified")
	}
}

func checkEmptyValuesRemainEmpty(t *testing.T, result [][]string) {
	if result[3][0] != "" || result[3][1] != "" {
		t.Error("Empty values should remain empty")
	}
}

func checkDeterministicBehavior(t *testing.T, d *Deidentifier, data [][]string, columnTypes []DataType, columnNames []string, result [][]string) {
	result2, err := d.Slices(data, columnTypes, columnNames)
	if err != nil {
		t.Fatalf("Second Slices failed: %v", err)
	}

	if result[0][0] != result2[0][0] {
		t.Error("Deidentification should be deterministic")
	}
}

func checkDifferentColumnNames(t *testing.T, data [][]string, columnTypes []DataType, result [][]string) {
	// Create a fresh deidentifier to ensure clean mapping table
	d2 := NewDeidentifier("test-secret-key-3")
	differentColumnNames := []string{"customer_name", "customer_email", "customer_phone", "customer_ssn"}
	result3, err := d2.Slices(data, columnTypes, differentColumnNames)
	if err != nil {
		t.Fatalf("Third Slices failed: %v", err)
	}

	if result[0][0] == result3[0][0] && data[0][0] != "" {
		t.Errorf("Different column names should produce different deidentified values: %s == %s", result[0][0], result3[0][0])
	}
}

func TestSlicesInference(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	// Test data with clear patterns
	data := [][]string{
		{"john.doe@example.com", "John Doe", "(555) 123-4567", "123-45-6789", "123 Main Street"},
		{"jane.smith@company.org", "Jane Smith", "555-987-6543", "987-65-4321", "456 Oak Avenue"},
		{"bob@test.co.uk", "Bob Johnson", "555.111.2222", "456-78-9012", "789 Pine Drive"},
	}

	// Test with no parameters (should infer)
	result, err := d.Slices(data)
	if err != nil {
		t.Fatalf("Slices with inference failed: %v", err)
	}

	if len(result) != len(data) {
		t.Errorf("Expected %d rows, got %d", len(data), len(result))
	}

	// Test that emails are deidentified (column 0)
	if result[0][0] == data[0][0] {
		t.Error("Email should be deidentified")
	}

	// Test that phone numbers are deidentified (column 2)
	if result[0][2] == data[0][2] {
		t.Error("Phone should be deidentified")
	}

	// Test with empty types slice (should infer)
	result2, err := d.Slices(data, []DataType{})
	if err != nil {
		t.Fatalf("Slices with empty slices failed: %v", err)
	}

	if len(result2) != len(data) {
		t.Errorf("Expected %d rows, got %d", len(data), len(result2))
	}
}

func TestInferColumnTypes(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	testCases := []struct {
		name     string
		data     [][]string
		expected []DataType
	}{
		{
			name: "Clear patterns",
			data: [][]string{
				{"john@example.com", "John Doe", "(555) 123-4567"},
				{"jane@company.org", "Jane Smith", "555-987-6543"},
			},
			expected: []DataType{TypeEmail, TypeName, TypePhone},
		},
		{
			name: "Mixed with some empty",
			data: [][]string{
				{"test@example.com", "", "123-45-6789"},
				{"", "Bob Smith", "987-65-4321"},
				{"admin@test.org", "Alice Brown", ""},
			},
			expected: []DataType{TypeEmail, TypeName, TypeSSN},
		},
		{
			name: "Generic fallback",
			data: [][]string{
				{"random text", "123ABC", "unknown format"},
				{"more text", "XYZ789", "another format"},
			},
			expected: []DataType{TypeGeneric, TypeGeneric, TypeGeneric},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := d.inferColumnTypes(tc.data)
			if err != nil {
				t.Fatalf("inferColumnTypes failed: %v", err)
			}

			if len(result) != len(tc.expected) {
				t.Fatalf("Expected %d types, got %d", len(tc.expected), len(result))
			}

			for i, expected := range tc.expected {
				if result[i] != expected {
					t.Errorf("Column %d: expected %v, got %v", i, expected, result[i])
				}
			}
		})
	}
}

func TestSlicesErrorCases(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	// Test empty data
	emptyData := [][]string{}
	result, err := d.Slices(emptyData)
	if err != nil {
		t.Fatalf("Empty data should not cause error: %v", err)
	}
	if len(result) != 0 {
		t.Error("Empty data should return empty result")
	}

	// Test mismatched column types and names
	data := [][]string{{"John", "john@example.com"}}
	_, err = d.Slices(data, []DataType{TypeName}, []string{"name", "email"})
	if err == nil {
		t.Error("Should error when column types don't match data columns")
	}

	_, err = d.Slices(data, []DataType{TypeName, TypeEmail}, []string{"name"})
	if err == nil {
		t.Error("Should error when column names don't match data columns")
	}

	// Test invalid parameter types
	_, err = d.Slices(data, "invalid")
	if err == nil {
		t.Error("Should error when first parameter is not []DataType")
	}

	_, err = d.Slices(data, []DataType{TypeName, TypeEmail}, 123)
	if err == nil {
		t.Error("Should error when second parameter is not []string")
	}
}

func BenchmarkSlicesDeidentification(b *testing.B) {
	d := NewDeidentifier("benchmark-key")

	// Create test data with 1000 rows
	data := make([][]string, 1000)
	for i := 0; i < 1000; i++ {
		data[i] = []string{"John Doe", "john@company.com", "555-123-4567", "123-45-6789"}
	}

	columnTypes := []DataType{TypeName, TypeEmail, TypePhone, TypeSSN}
	columnNames := []string{"name", "email", "phone", "ssn"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := d.Slices(data, columnTypes, columnNames)
		if err != nil {
			b.Fatalf("Slices failed: %v", err)
		}
	}
}

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
	
	result, err := d.DeidentifyTable(table)
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
	
	// Same value in different columns should map to same result
	email1 := d.generateEmail("test@company.com")
	email2 := d.generateEmail("test@company.com")
	
	if email1 != email2 {
		t.Error("Same input should produce same output for referential integrity")
	}
	
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
	
	result1, _ := d.DeidentifyTable(table1)
	result2, _ := d.DeidentifyTable(table2)
	
	// Should be different because column names are different (different mapping tables)
	val1 := result1.Columns[0].Values[0]
	val2 := result2.Columns[0].Values[0]
	
	if val1 == val2 {
		t.Error("Different column names should produce different mappings")
	}
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
		d.DeidentifyTable(table)
	}
}

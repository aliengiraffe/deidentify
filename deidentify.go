package deidentify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type DataType int

const (
	TypeName DataType = iota
	TypeEmail
	TypePhone
	TypeSSN
	TypeCreditCard
	TypeAddress
	TypeGeneric
)

type Column struct {
	Name     string
	DataType DataType
	Values   []interface{}
}

type Table struct {
	Columns []Column
}

type Deidentifier struct {
	secretKey     []byte
	mappingTables map[string]map[string]string
	mutex         sync.RWMutex
}

// NewDeidentifier creates a new deidentifier with a secret key
func NewDeidentifier(secretKey string) *Deidentifier {
	return &Deidentifier{
		secretKey:     []byte(secretKey),
		mappingTables: make(map[string]map[string]string),
	}
}

// DeidentifyText identifies and deidentifies PII from a text string
func (d *Deidentifier) DeidentifyText(text string) (string, error) {
	if text == "" {
		return "", nil
	}

	// Replace all PII types using regex patterns
	result := text

	// Process emails
	emailRegex := regexp.MustCompile(emailRegexPattern)
	result = emailRegex.ReplaceAllStringFunc(result, func(email string) string {
		deidentified, err := d.deidentifyValue(email, TypeEmail, "email")
		if err != nil {
			return "[EMAIL REDACTION ERROR]"
		}
		return deidentified
	})

	// Process phone numbers
	phoneRegex := regexp.MustCompile(phoneRegexPattern)
	result = phoneRegex.ReplaceAllStringFunc(result, func(phone string) string {
		deidentified, err := d.deidentifyValue(phone, TypePhone, "phone")
		if err != nil {
			return "[PHONE REDACTION ERROR]"
		}
		return deidentified
	})

	// Process SSNs
	ssnRegex := regexp.MustCompile(ssnRegexPattern)
	result = ssnRegex.ReplaceAllStringFunc(result, func(ssn string) string {
		// Verify it's likely an SSN, not just any 9 digits
		ssnHyphenRegex := regexp.MustCompile(ssnHyphenRegexPattern)
		ssnSpaceRegex := regexp.MustCompile(ssnSpaceRegexPattern)
		ssnContextRegex := regexp.MustCompile(ssnContextRegexPattern)

		// Get the raw digits without any separators
		rawDigits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(ssn, "")

		// Check if it's formatted like an SSN (with hyphens or spaces) or mentioned with SSN context
		isFormatted := ssnHyphenRegex.MatchString(ssn) || ssnSpaceRegex.MatchString(ssn)
		hasSSNContext := ssnContextRegex.MatchString(text)

		if !isFormatted && !hasSSNContext {
			// If not formatted like an SSN and no SSN context, only detect if exactly 9 digits
			if len(rawDigits) == 9 {
				// Assume it's an SSN if it's exactly 9 digits
				deidentified, err := d.deidentifyValue(ssn, TypeSSN, "ssn")
				if err != nil {
					return "[SSN REDACTION ERROR]"
				}
				return deidentified
			}
			return ssn
		}

		deidentified, err := d.deidentifyValue(ssn, TypeSSN, "ssn")
		if err != nil {
			return "[SSN REDACTION ERROR]"
		}
		return deidentified
	})

	// Process credit cards
	ccRegex := regexp.MustCompile(creditCardRegexPattern)
	result = ccRegex.ReplaceAllStringFunc(result, func(cc string) string {
		deidentified, err := d.deidentifyValue(cc, TypeCreditCard, "credit_card")
		if err != nil {
			return "[CC REDACTION ERROR]"
		}
		return deidentified
	})

	// Handle addresses that appear in running text with context
	// This pattern handles addresses that appear after key words/phrases like "lives at", "located at", etc.
	contextAddressPattern := regexp.MustCompile(`(?i)(lives at|located at|resides at|found at|situated at|at address|address is|at location|based at) (\d+[^\n\.]*?(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Place|Pl|Boulevard|Blvd|Way)[^\n\.]*)`)
	result = contextAddressPattern.ReplaceAllStringFunc(result, func(text string) string {
		parts := contextAddressPattern.FindStringSubmatch(text)
		if len(parts) < 3 {
			return text
		}

		prefix := parts[1]
		address := strings.TrimSpace(parts[2])

		deidentified, err := d.deidentifyValue(address, TypeAddress, "address")
		if err != nil {
			return text
		}

		return prefix + " " + deidentified
	})

	// Process special address patterns first (that might not be caught by the main pattern)
	// 1. Process addresses with country names (like "123 Orchard Road, Singapore")
	specialAddr1Regex := regexp.MustCompile(specialAddressPattern1)
	result = specialAddr1Regex.ReplaceAllStringFunc(result, func(addr string) string {
		deidentified, err := d.deidentifyValue(addr, TypeAddress, "address")
		if err != nil {
			return "[ADDRESS REDACTION ERROR]"
		}
		return deidentified
	})

	// 2. Process addresses with city and country (like "15 Rue de Rivoli, Paris, France")
	specialAddr2Regex := regexp.MustCompile(specialAddressPattern2)
	result = specialAddr2Regex.ReplaceAllStringFunc(result, func(addr string) string {
		deidentified, err := d.deidentifyValue(addr, TypeAddress, "address")
		if err != nil {
			return "[ADDRESS REDACTION ERROR]"
		}
		return deidentified
	})

	// 3. Process addresses that might have a label before them in text
	specialAddr3Regex := regexp.MustCompile(specialAddressPattern3)
	result = specialAddr3Regex.ReplaceAllStringFunc(result, func(addr string) string {
		parts := strings.SplitN(addr, " ", 2)
		if len(parts) < 2 {
			return addr
		}

		prefix := parts[0]
		address := strings.TrimSpace(parts[1])

		deidentified, err := d.deidentifyValue(address, TypeAddress, "address")
		if err != nil {
			return addr
		}

		return prefix + " " + deidentified
	})

	// Process names (more complex, less precise)
	// This is a simplistic approach - production systems would use NER models
	nameRegex := regexp.MustCompile(nameRegexPattern)
	result = nameRegex.ReplaceAllStringFunc(result, func(name string) string {
		// Skip if it looks like an address or contains common words
		addressWordRegex := regexp.MustCompile(addressWordRegexPattern)
		internationalAddressRegex := regexp.MustCompile(internationalAddressRegexPattern)
		countryRegex := regexp.MustCompile(countryNameRegexPattern)
		cityRegex := regexp.MustCompile(cityRegexPattern)

		// Check if this is in an address context - either by our global pattern or surrounding
		// content that suggests it's part of an address
		if addressWordRegex.MatchString(name) ||
			internationalAddressRegex.MatchString(name) ||
			countryRegex.MatchString(name) ||
			cityRegex.MatchString(name) {
			return name
		}

		deidentified, err := d.deidentifyValue(name, TypeName, "name")
		if err != nil {
			return "[NAME REDACTION ERROR]"
		}
		return deidentified
	})

	// Process standard addresses (with or without countries/ISO codes)
	addrRegex := regexp.MustCompile(addressRegexPattern)
	result = addrRegex.ReplaceAllStringFunc(result, func(addr string) string {
		deidentified, err := d.deidentifyValue(addr, TypeAddress, "address")
		if err != nil {
			return "[ADDRESS REDACTION ERROR]"
		}
		return deidentified
	})

	return result, nil
}

// DeidentifyEmail is a convenience method to deidentify a single email
func (d *Deidentifier) DeidentifyEmail(email string) (string, error) {
	return d.deidentifyValue(email, TypeEmail, "email")
}

// DeidentifyPhone is a convenience method to deidentify a single phone number
func (d *Deidentifier) DeidentifyPhone(phone string) (string, error) {
	return d.deidentifyValue(phone, TypePhone, "phone")
}

// DeidentifySSN is a convenience method to deidentify a single SSN
func (d *Deidentifier) DeidentifySSN(ssn string) (string, error) {
	return d.deidentifyValue(ssn, TypeSSN, "ssn")
}

// DeidentifyName is a convenience method to deidentify a single name
func (d *Deidentifier) DeidentifyName(name string) (string, error) {
	return d.deidentifyValue(name, TypeName, "name")
}

// DeidentifyAddress is a convenience method to deidentify a single address
func (d *Deidentifier) DeidentifyAddress(address string) (string, error) {
	// Check for a label prefix (like "European HQ:") and extract the actual address part
	address = strings.TrimSpace(address)
	colonIndex := strings.Index(address, ":")
	actualAddr := address
	if colonIndex >= 0 {
		actualAddr = strings.TrimSpace(address[colonIndex+1:])
	}

	// First try the special address patterns
	specialAddr1Regex := regexp.MustCompile(specialAddressPattern1)
	if specialAddr1Regex.MatchString(actualAddr) {
		deidentified, err := d.deidentifyValue(actualAddr, TypeAddress, "address")
		if err != nil {
			return "", err
		}

		// If there was a label, preserve it
		if colonIndex >= 0 {
			return address[:colonIndex+1] + " " + deidentified, nil
		}
		return deidentified, nil
	}

	specialAddr2Regex := regexp.MustCompile(specialAddressPattern2)
	if specialAddr2Regex.MatchString(actualAddr) {
		deidentified, err := d.deidentifyValue(actualAddr, TypeAddress, "address")
		if err != nil {
			return "", err
		}

		// If there was a label, preserve it
		if colonIndex >= 0 {
			return address[:colonIndex+1] + " " + deidentified, nil
		}
		return deidentified, nil
	}

	specialAddr3Regex := regexp.MustCompile(specialAddressPattern3)
	if specialAddr3Regex.MatchString(actualAddr) {
		deidentified, err := d.deidentifyValue(actualAddr, TypeAddress, "address")
		if err != nil {
			return "", err
		}

		// If there was a label, preserve it
		if colonIndex >= 0 {
			return address[:colonIndex+1] + " " + deidentified, nil
		}
		return deidentified, nil
	}

	// Fall back to standard address pattern
	deidentified, err := d.deidentifyValue(actualAddr, TypeAddress, "address")
	if err != nil {
		return "", err
	}

	// If there was a label, preserve it
	if colonIndex >= 0 {
		return address[:colonIndex+1] + " " + deidentified, nil
	}
	return deidentified, nil
}

// DeidentifyCreditCard is a convenience method to deidentify a single credit card number
func (d *Deidentifier) DeidentifyCreditCard(cc string) (string, error) {
	return d.deidentifyValue(cc, TypeCreditCard, "credit_card")
}

// DeidentifyTable processes an entire table
func (d *Deidentifier) DeidentifyTable(table *Table) (*Table, error) {
	result := &Table{
		Columns: make([]Column, len(table.Columns)),
	}

	for i, col := range table.Columns {
		deidentifiedValues := make([]interface{}, len(col.Values))

		for j, value := range col.Values {
			if value == nil {
				deidentifiedValues[j] = nil
				continue
			}

			strValue := fmt.Sprintf("%v", value)
			deidentifiedValue, err := d.deidentifyValue(strValue, col.DataType, col.Name)
			if err != nil {
				return nil, fmt.Errorf("error deidentifying column %s, row %d: %w", col.Name, j, err)
			}
			deidentifiedValues[j] = deidentifiedValue
		}

		result.Columns[i] = Column{
			Name:     col.Name,
			DataType: col.DataType,
			Values:   deidentifiedValues,
		}
	}

	return result, nil
}

// deidentifyValue handles individual value deidentification
func (d *Deidentifier) deidentifyValue(value string, dataType DataType, columnName string) (string, error) {
	if value == "" {
		return "", nil
	}

	// Check for existing mapping first for deterministic results
	if mapped := d.getMapping(columnName, value); mapped != "" {
		return mapped, nil
	}

	var result string
	var err error

	switch dataType {
	case TypeName:
		result = d.generateName(value)
	case TypeEmail:
		result = d.generateEmail(value)
	case TypePhone:
		result = d.generatePhone(value)
	case TypeSSN:
		result = d.generateSSN(value)
	case TypeCreditCard:
		result = d.generateCreditCard(value)
	case TypeAddress:
		result = d.generateAddress(value)
	default:
		result = d.generateGeneric(value)
	}

	if err != nil {
		return "", err
	}

	// Store mapping for consistency
	d.setMapping(columnName, value, result)
	return result, nil
}

// generateName creates a deterministic fake name
func (d *Deidentifier) generateName(original string) string {
	hash := d.deterministicHash(original)
	firstIdx := d.hashToIndex(hash[:8], len(firstNameOptions))
	lastIdx := d.hashToIndex(hash[8:16], len(lastNameOptions))

	return fmt.Sprintf("%s %s", firstNameOptions[firstIdx], lastNameOptions[lastIdx])
}

// generateEmail creates a deterministic fake email
func (d *Deidentifier) generateEmail(original string) string {
	hash := d.deterministicHash(original)
	userIdx := d.hashToIndex(hash[:8], len(emailUsernameOptions))
	domainIdx := d.hashToIndex(hash[8:16], len(emailDomainOptions))
	suffix := d.hashToIndex(hash[16:24], 9999)

	return fmt.Sprintf("%s%d@%s", emailUsernameOptions[userIdx], suffix, emailDomainOptions[domainIdx])
}

// generatePhone creates a deterministic fake phone number preserving format
func (d *Deidentifier) generatePhone(original string) string {
	// Extract format and components
	phoneRegex := regexp.MustCompile(phoneFormatRegexPattern)
	matches := phoneRegex.FindStringSubmatch(original)

	if len(matches) == 0 {
		// Fallback for non-standard formats
		return d.generateGeneric(original)
	}

	prefix := matches[1]        // +1 or country code (preserve)
	openParen := matches[2]     // ( or empty (preserve)
	areaCode := matches[3]      // 3 digits area code (preserve)
	afterAreaCode := matches[4] // ) or . or - or space or empty (preserve)
	_ = matches[5]              // exchange - will be replaced
	separator := matches[6]     // . or - or space (preserve)
	_ = matches[7]              // last 4 digits - will be replaced

	hash := d.deterministicHash(original)
	exchange := 200 + d.hashToIndex(hash[:8], 799)   // Valid exchange range
	number := 1000 + d.hashToIndex(hash[8:16], 8999) // Valid number range

	// Create proper formatting
	return fmt.Sprintf("%s%s%s%s%03d%s%04d",
		prefix, openParen, areaCode, afterAreaCode, exchange, separator, number)
}

// generateSSN creates a deterministic fake SSN with valid format
func (d *Deidentifier) generateSSN(original string) string {
	hash := d.deterministicHash(original)

	// Avoid invalid SSN patterns (666, 900-999 area numbers)
	area := 100 + d.hashToIndex(hash[:8], 565) // 100-665
	if area == 666 {
		area = 667
	}

	group := 1 + d.hashToIndex(hash[8:16], 99)     // 01-99
	serial := 1 + d.hashToIndex(hash[16:24], 9999) // 0001-9999

	return fmt.Sprintf("%03d-%02d-%04d", area, group, serial)
}

// generateCreditCard creates a deterministic fake credit card with valid Luhn checksum
func (d *Deidentifier) generateCreditCard(original string) string {
	// Use test card prefixes (4000 for Visa test cards)
	hash := d.deterministicHash(original)

	// Generate 15 digits (4000 + 11 more digits)
	cardNumber := "4000"
	for i := 0; i < 11; i++ {
		digit := d.hashToIndex(hash[i*2:i*2+2], 10)
		cardNumber += strconv.Itoa(digit)
	}

	// Calculate and append Luhn checksum
	checkDigit := d.calculateLuhnCheckDigit(cardNumber)
	cardNumber += strconv.Itoa(checkDigit)

	// Format with spaces every 4 digits
	formatted := ""
	for i, char := range cardNumber {
		if i > 0 && i%4 == 0 {
			formatted += " "
		}
		formatted += string(char)
	}

	return formatted
}

// generateAddress creates a deterministic fake address
func (d *Deidentifier) generateAddress(original string) string {
	hash := d.deterministicHash(original)
	number := 1 + d.hashToIndex(hash[:8], 9999)
	streetIdx := d.hashToIndex(hash[8:16], len(streetNameOptions))

	return fmt.Sprintf("%d %s", number, streetNameOptions[streetIdx])
}

// generateGeneric creates a deterministic replacement for generic data
func (d *Deidentifier) generateGeneric(original string) string {
	hash := d.deterministicHash(original)
	return fmt.Sprintf("DATA_%s", hex.EncodeToString(hash[:8]))
}

// deterministicHash creates a consistent hash using HMAC
func (d *Deidentifier) deterministicHash(input string) []byte {
	h := hmac.New(sha256.New, d.secretKey)
	h.Write([]byte(input))
	return h.Sum(nil)
}

// hashToIndex converts hash bytes to an index within range
func (d *Deidentifier) hashToIndex(hashBytes []byte, max int) int {
	if len(hashBytes) == 0 || max <= 0 {
		return 0
	}

	// Convert bytes to big int and mod by max
	bigInt := new(big.Int).SetBytes(hashBytes)
	return int(bigInt.Mod(bigInt, big.NewInt(int64(max))).Int64())
}

// calculateLuhnCheckDigit calculates the Luhn checksum digit
func (d *Deidentifier) calculateLuhnCheckDigit(cardNumber string) int {
	sum := 0
	alternate := true

	// Process digits from right to left (excluding check digit position)
	for i := len(cardNumber) - 1; i >= 0; i-- {
		digit, _ := strconv.Atoi(string(cardNumber[i]))

		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}

		sum += digit
		alternate = !alternate
	}

	return (10 - (sum % 10)) % 10
}

// Mapping table functions for consistency
func (d *Deidentifier) getMapping(columnName, original string) string {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if columnMap, exists := d.mappingTables[columnName]; exists {
		return columnMap[original]
	}
	return ""
}

func (d *Deidentifier) setMapping(columnName, original, replacement string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.mappingTables[columnName] == nil {
		d.mappingTables[columnName] = make(map[string]string)
	}
	d.mappingTables[columnName][original] = replacement
}

// ClearMappings clears all stored mappings (useful for testing)
func (d *Deidentifier) ClearMappings() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.mappingTables = make(map[string]map[string]string)
}

// DeidentifySlices processes a slice of string slices ([][]string)
// Each inner slice represents a row of data
// Optional parameters:
//   - columnTypes: DataType for each column (will infer if not provided)
//   - columnNames: names for each column (will generate if not provided)
//
// Usage: DeidentifySlices(data) or DeidentifySlices(data, columnTypes) or DeidentifySlices(data, columnTypes, columnNames)
func (d *Deidentifier) DeidentifySlices(data [][]string, optional ...interface{}) ([][]string, error) {
	if len(data) == 0 {
		return [][]string{}, nil
	}

	// Parse optional parameters
	var columnTypes []DataType
	var columnNames []string

	if len(optional) > 0 {
		// First optional parameter should be columnTypes
		if types, ok := optional[0].([]DataType); ok {
			columnTypes = types
		} else {
			return nil, fmt.Errorf("first optional parameter must be []DataType")
		}
	}

	if len(optional) > 1 {
		// Second optional parameter should be columnNames
		if names, ok := optional[1].([]string); ok {
			columnNames = names
		} else {
			return nil, fmt.Errorf("second optional parameter must be []string")
		}
	}

	// Determine the number of columns from the first row
	var numCols int
	if len(data) > 0 {
		numCols = len(data[0])
	}

	// Generate default column names if not provided
	if len(columnNames) == 0 {
		columnNames = make([]string, numCols)
		for i := 0; i < numCols; i++ {
			columnNames[i] = fmt.Sprintf("column_%d", i)
		}
	}

	// Infer column types if not provided
	if len(columnTypes) == 0 {
		var err error
		columnTypes, err = d.inferColumnTypes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to infer column types: %w", err)
		}
	}

	// Validate that column types and names match the data structure
	if len(columnTypes) != numCols || len(columnNames) != numCols {
		return nil, fmt.Errorf("mismatch between data columns (%d) and provided column types (%d) or names (%d)",
			numCols, len(columnTypes), len(columnNames))
	}

	// Create result matrix with same dimensions
	result := make([][]string, len(data))

	// Process each row
	for i, row := range data {
		// Create a new row with same length
		resultRow := make([]string, len(row))

		// Process each cell in the row
		for j, value := range row {
			if value == "" {
				resultRow[j] = ""
				continue
			}

			// Get the column type and name for this cell
			colType := columnTypes[j]
			colName := columnNames[j]

			// Deidentify the value
			deidentifiedValue, err := d.deidentifyValue(value, colType, colName)
			if err != nil {
				return nil, fmt.Errorf("error deidentifying row %d, column %d (%s): %w", i, j, colName, err)
			}

			resultRow[j] = deidentifiedValue
		}

		result[i] = resultRow
	}

	return result, nil
}

// inferColumnTypes analyzes the data to determine the most likely data type for each column
func (d *Deidentifier) inferColumnTypes(data [][]string) ([]DataType, error) {
	if len(data) == 0 {
		return []DataType{}, nil
	}

	numCols := len(data[0])
	columnTypes := make([]DataType, numCols)

	// Compile regex patterns once for efficiency
	emailRegex := regexp.MustCompile(emailRegexPattern)
	phoneRegex := regexp.MustCompile(phoneRegexPattern)
	ssnRegex := regexp.MustCompile(ssnRegexPattern)
	ccRegex := regexp.MustCompile(creditCardRegexPattern)
	nameRegex := regexp.MustCompile(nameRegexPattern)
	addressRegex := regexp.MustCompile(addressRegexPattern)
	addressWordRegex := regexp.MustCompile(addressWordRegexPattern)

	// For each column, analyze a sample of values to determine type
	for col := 0; col < numCols; col++ {
		typeScores := map[DataType]int{
			TypeEmail:      0,
			TypePhone:      0,
			TypeSSN:        0,
			TypeCreditCard: 0,
			TypeAddress:    0,
			TypeName:       0,
			TypeGeneric:    0,
		}

		sampleSize := len(data)
		if sampleSize > 10 {
			sampleSize = 10 // Sample first 10 rows for performance
		}

		validValues := 0

		for row := 0; row < sampleSize; row++ {
			if col >= len(data[row]) || data[row][col] == "" {
				continue // Skip empty values
			}

			value := strings.TrimSpace(data[row][col])
			if value == "" {
				continue
			}

			validValues++

			// Check each pattern and score
			if emailRegex.MatchString(value) {
				typeScores[TypeEmail] += 10
			}
			if phoneRegex.MatchString(value) {
				typeScores[TypePhone] += 10
			}
			if ssnRegex.MatchString(value) {
				typeScores[TypeSSN] += 10
			}
			if ccRegex.MatchString(value) {
				typeScores[TypeCreditCard] += 10
			}
			if addressRegex.MatchString(value) || addressWordRegex.MatchString(value) {
				typeScores[TypeAddress] += 10
			}
			if nameRegex.MatchString(value) && !addressWordRegex.MatchString(value) {
				typeScores[TypeName] += 5 // Lower weight since names are harder to detect
			}
		}

		// Find the type with the highest score
		var bestType DataType = TypeGeneric
		var maxScore int = 0

		for dataType, score := range typeScores {
			if score > maxScore {
				maxScore = score
				bestType = dataType
			}
		}

		// Use the best type if we have a reasonable confidence
		// For name detection, we use a lower threshold since it's harder to detect reliably
		var threshold int
		if bestType == TypeName {
			threshold = validValues * 3 // 30% threshold for names
		} else {
			threshold = validValues * 5 // 50% threshold for other types
		}

		if validValues > 0 && maxScore >= threshold {
			columnTypes[col] = bestType
		} else {
			columnTypes[col] = TypeGeneric
		}
	}

	return columnTypes, nil
}

// GenerateSecretKey generates a cryptographically secure random key
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

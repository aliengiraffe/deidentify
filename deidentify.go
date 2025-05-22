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

// DataType represents the type of personally identifiable information
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

// Column represents a single column in a table with its data type and values
type Column struct {
	Name     string
	DataType DataType
	Values   []interface{}
}

// Deidentifier handles the deidentification of PII data
type Deidentifier struct {
	secretKey     []byte
	mappingTables map[string]map[string]string
	mutex         sync.RWMutex
}

// Table represents a collection of columns
type Table struct {
	Columns []Column
}

// patternSet holds compiled regex patterns for type inference
type patternSet struct {
	email       *regexp.Regexp
	phone       *regexp.Regexp
	ssn         *regexp.Regexp
	creditCard  *regexp.Regexp
	name        *regexp.Regexp
	address     *regexp.Regexp
	addressWord *regexp.Regexp
}

// slicesConfig holds the configuration for slice processing
type slicesConfig struct {
	columnTypes []DataType
	columnNames []string
	numCols     int
}

// Address is a convenience method to deidentify a single address
func (d *Deidentifier) Address(address string) (string, error) {
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

// ClearMappings clears all stored mappings (useful for testing)
func (d *Deidentifier) ClearMappings() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.mappingTables = make(map[string]map[string]string)
}

// CreditCard is a convenience method to deidentify a single credit card number
func (d *Deidentifier) CreditCard(cc string) (string, error) {
	return d.deidentifyValue(cc, TypeCreditCard, "credit_card")
}

// Email is a convenience method to deidentify a single email
func (d *Deidentifier) Email(email string) (string, error) {
	return d.deidentifyValue(email, TypeEmail, "email")
}

// Name is a convenience method to deidentify a single name
func (d *Deidentifier) Name(name string) (string, error) {
	return d.deidentifyValue(name, TypeName, "name")
}

// Phone is a convenience method to deidentify a single phone number
func (d *Deidentifier) Phone(phone string) (string, error) {
	return d.deidentifyValue(phone, TypePhone, "phone")
}

// SSN is a convenience method to deidentify a single SSN
func (d *Deidentifier) SSN(ssn string) (string, error) {
	return d.deidentifyValue(ssn, TypeSSN, "ssn")
}

// Slices processes a slice of string slices ([][]string)
// Each inner slice represents a row of data
// Optional parameters:
//   - columnTypes: DataType for each column (will infer if not provided)
//   - columnNames: names for each column (will generate if not provided)
//
// Usage: Slices(data) or Slices(data, columnTypes) or Slices(data, columnTypes, columnNames)
func (d *Deidentifier) Slices(data [][]string, optional ...interface{}) ([][]string, error) {
	if len(data) == 0 {
		return [][]string{}, nil
	}

	config, err := d.parseSlicesParameters(data, optional...)
	if err != nil {
		return nil, err
	}

	return d.processSliceData(data, config)
}

// Table processes an entire table
func (d *Deidentifier) Table(table *Table) (*Table, error) {
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

// Text identifies and deidentifies PII from a text string
func (d *Deidentifier) Text(text string) (string, error) {
	if text == "" {
		return "", nil
	}

	result := text
	result = d.processEmails(result)
	result = d.processPhones(result)
	result = d.processSSNs(result, text)
	result = d.processCreditCards(result)
	result = d.processContextAddresses(result)
	result = d.processSpecialAddresses(result)
	result = d.processNames(result)
	result = d.processStandardAddresses(result)

	return result, nil
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

// NewDeidentifier creates a new deidentifier with a secret key
func NewDeidentifier(secretKey string) *Deidentifier {
	return &Deidentifier{
		secretKey:     []byte(secretKey),
		mappingTables: make(map[string]map[string]string),
	}
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

// compilePatterns compiles all regex patterns once for efficiency
func (d *Deidentifier) compilePatterns() *patternSet {
	return &patternSet{
		email:       regexp.MustCompile(emailRegexPattern),
		phone:       regexp.MustCompile(phoneRegexPattern),
		ssn:         regexp.MustCompile(ssnRegexPattern),
		creditCard:  regexp.MustCompile(creditCardRegexPattern),
		name:        regexp.MustCompile(nameRegexPattern),
		address:     regexp.MustCompile(addressRegexPattern),
		addressWord: regexp.MustCompile(addressWordRegexPattern),
	}
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

	// Store mapping for consistency
	d.setMapping(columnName, value, result)
	return result, nil
}

// deterministicHash creates a consistent hash using HMAC
func (d *Deidentifier) deterministicHash(input string) []byte {
	h := hmac.New(sha256.New, d.secretKey)
	h.Write([]byte(input))
	return h.Sum(nil)
}

// findHighestScoringType finds the type with the highest score
func (d *Deidentifier) findHighestScoringType(typeScores map[DataType]int) (DataType, int) {
	bestType := TypeGeneric
	maxScore := 0

	for dataType, score := range typeScores {
		if score > maxScore {
			maxScore = score
			bestType = dataType
		}
	}
	return bestType, maxScore
}

// generateAddress creates a deterministic fake address
func (d *Deidentifier) generateAddress(original string) string {
	hash := d.deterministicHash(original)
	number := 1 + d.hashToIndex(hash[:8], 9999)
	streetIdx := d.hashToIndex(hash[8:16], len(streetNameOptions))

	return fmt.Sprintf("%d %s", number, streetNameOptions[streetIdx])
}

// generateCreditCard creates a deterministic fake credit card with valid Luhn checksum
func (d *Deidentifier) generateCreditCard(original string) string {
	// Use test card prefixes (4000 for Visa test cards)
	hash := d.deterministicHash(original)

	// Generate 15 digits (4000 + 11 more digits)
	cardNumber := "4000"
	for i := range 11 {
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

// generateEmail creates a deterministic fake email
func (d *Deidentifier) generateEmail(original string) string {
	hash := d.deterministicHash(original)
	userIdx := d.hashToIndex(hash[:8], len(emailUsernameOptions))
	domainIdx := d.hashToIndex(hash[8:16], len(emailDomainOptions))
	suffix := d.hashToIndex(hash[16:24], 9999)

	return fmt.Sprintf("%s%d@%s", emailUsernameOptions[userIdx], suffix, emailDomainOptions[domainIdx])
}

// generateGeneric creates a deterministic replacement for generic data
func (d *Deidentifier) generateGeneric(original string) string {
	hash := d.deterministicHash(original)
	return fmt.Sprintf("DATA_%s", hex.EncodeToString(hash[:8]))
}

// generateName creates a deterministic fake name
func (d *Deidentifier) generateName(original string) string {
	hash := d.deterministicHash(original)
	firstIdx := d.hashToIndex(hash[:8], len(firstNameOptions))
	lastIdx := d.hashToIndex(hash[8:16], len(lastNameOptions))

	return fmt.Sprintf("%s %s", firstNameOptions[firstIdx], lastNameOptions[lastIdx])
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

// getConfidenceThreshold returns the confidence threshold for a given type
func (d *Deidentifier) getConfidenceThreshold(dataType DataType, validValues int) int {
	if dataType == TypeName {
		return validValues * 3 // 30% threshold for names
	}
	return validValues * 5 // 50% threshold for other types
}

// getMapping retrieves an existing mapping for deterministic results
func (d *Deidentifier) getMapping(columnName, original string) string {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if columnMap, exists := d.mappingTables[columnName]; exists {
		return columnMap[original]
	}
	return ""
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

// inferColumnTypes analyzes the data to determine the most likely data type for each column
func (d *Deidentifier) inferColumnTypes(data [][]string) ([]DataType, error) {
	if len(data) == 0 {
		return []DataType{}, nil
	}

	numCols := len(data[0])
	columnTypes := make([]DataType, numCols)
	patterns := d.compilePatterns()

	for col := 0; col < numCols; col++ {
		columnTypes[col] = d.inferSingleColumnType(data, col, patterns)
	}

	return columnTypes, nil
}

// inferOrValidateColumnTypes infers column types if not provided
func (d *Deidentifier) inferOrValidateColumnTypes(data [][]string, config *slicesConfig) error {
	if len(config.columnTypes) == 0 {
		var err error
		config.columnTypes, err = d.inferColumnTypes(data)
		if err != nil {
			return fmt.Errorf("failed to infer column types: %w", err)
		}
	}
	return nil
}

// inferSingleColumnType analyzes a single column to determine its type
func (d *Deidentifier) inferSingleColumnType(data [][]string, col int, patterns *patternSet) DataType {
	typeScores := d.initializeTypeScores()
	validValues := d.scoreColumnValues(data, col, patterns, typeScores)
	return d.selectBestType(typeScores, validValues)
}

// initializeTypeScores creates a map with zero scores for all types
func (d *Deidentifier) initializeTypeScores() map[DataType]int {
	return map[DataType]int{
		TypeEmail:      0,
		TypePhone:      0,
		TypeSSN:        0,
		TypeCreditCard: 0,
		TypeAddress:    0,
		TypeName:       0,
		TypeGeneric:    0,
	}
}

// isAddressContext checks if a name candidate is actually part of an address
func (d *Deidentifier) isAddressContext(name string) bool {
	addressWordRegex := regexp.MustCompile(addressWordRegexPattern)
	internationalAddressRegex := regexp.MustCompile(internationalAddressRegexPattern)
	countryRegex := regexp.MustCompile(countryNameRegexPattern)
	cityRegex := regexp.MustCompile(cityRegexPattern)

	return addressWordRegex.MatchString(name) ||
		internationalAddressRegex.MatchString(name) ||
		countryRegex.MatchString(name) ||
		cityRegex.MatchString(name)
}

// isValidValue checks if a cell contains a valid value for analysis
func (d *Deidentifier) isValidValue(data [][]string, row, col int) bool {
	return col < len(data[row]) && data[row][col] != "" && strings.TrimSpace(data[row][col]) != ""
}

// parseOptionalParameters extracts columnTypes and columnNames from optional parameters
func (d *Deidentifier) parseOptionalParameters(optional []interface{}, config *slicesConfig) error {
	if len(optional) > 0 {
		if types, ok := optional[0].([]DataType); ok {
			config.columnTypes = types
		} else {
			return fmt.Errorf("first optional parameter must be []DataType")
		}
	}

	if len(optional) > 1 {
		if names, ok := optional[1].([]string); ok {
			config.columnNames = names
		} else {
			return fmt.Errorf("second optional parameter must be []string")
		}
	}

	return nil
}

// parseSlicesParameters parses and validates the optional parameters for Slices
func (d *Deidentifier) parseSlicesParameters(data [][]string, optional ...interface{}) (*slicesConfig, error) {
	config := &slicesConfig{
		numCols: len(data[0]),
	}

	if err := d.parseOptionalParameters(optional, config); err != nil {
		return nil, err
	}

	if err := d.setDefaultColumnNames(config); err != nil {
		return nil, err
	}

	if err := d.inferOrValidateColumnTypes(data, config); err != nil {
		return nil, err
	}

	return config, d.validateSlicesConfig(config)
}

// processContextAddresses handles addresses with contextual clues
func (d *Deidentifier) processContextAddresses(text string) string {
	contextAddressPattern := regexp.MustCompile(`(?i)(lives at|located at|resides at|found at|situated at|at address|address is|at location|based at) (\d+[^\n\.]*?(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Place|Pl|Boulevard|Blvd|Way)[^\n\.]*)`)
	return contextAddressPattern.ReplaceAllStringFunc(text, func(match string) string {
		parts := contextAddressPattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}

		prefix := parts[1]
		address := strings.TrimSpace(parts[2])

		deidentified, err := d.deidentifyValue(address, TypeAddress, "address")
		if err != nil {
			return match
		}

		return prefix + " " + deidentified
	})
}

// processCreditCards handles credit card deidentification
func (d *Deidentifier) processCreditCards(text string) string {
	ccRegex := regexp.MustCompile(creditCardRegexPattern)
	return ccRegex.ReplaceAllStringFunc(text, func(cc string) string {
		deidentified, err := d.deidentifyValue(cc, TypeCreditCard, "credit_card")
		if err != nil {
			return "[CC REDACTION ERROR]"
		}
		return deidentified
	})
}

// processEmails handles email deidentification
func (d *Deidentifier) processEmails(text string) string {
	emailRegex := regexp.MustCompile(emailRegexPattern)
	return emailRegex.ReplaceAllStringFunc(text, func(email string) string {
		deidentified, err := d.deidentifyValue(email, TypeEmail, "email")
		if err != nil {
			return "[EMAIL REDACTION ERROR]"
		}
		return deidentified
	})
}

// processNames handles name deidentification with address context checking
func (d *Deidentifier) processNames(text string) string {
	nameRegex := regexp.MustCompile(nameRegexPattern)
	return nameRegex.ReplaceAllStringFunc(text, func(name string) string {
		if d.isAddressContext(name) {
			return name
		}

		deidentified, err := d.deidentifyValue(name, TypeName, "name")
		if err != nil {
			return "[NAME REDACTION ERROR]"
		}
		return deidentified
	})
}

// processPhones handles phone number deidentification
func (d *Deidentifier) processPhones(text string) string {
	phoneRegex := regexp.MustCompile(phoneRegexPattern)
	return phoneRegex.ReplaceAllStringFunc(text, func(phone string) string {
		deidentified, err := d.deidentifyValue(phone, TypePhone, "phone")
		if err != nil {
			return "[PHONE REDACTION ERROR]"
		}
		return deidentified
	})
}

// processSliceData processes the slice data using the provided configuration
func (d *Deidentifier) processSliceData(data [][]string, config *slicesConfig) ([][]string, error) {
	result := make([][]string, len(data))

	for i, row := range data {
		processedRow, err := d.processSliceRow(row, config, i)
		if err != nil {
			return nil, err
		}
		result[i] = processedRow
	}

	return result, nil
}

// processSliceRow processes a single row of slice data
func (d *Deidentifier) processSliceRow(row []string, config *slicesConfig, rowIndex int) ([]string, error) {
	resultRow := make([]string, len(row))

	for j, value := range row {
		if value == "" {
			resultRow[j] = ""
			continue
		}

		deidentifiedValue, err := d.deidentifyValue(value, config.columnTypes[j], config.columnNames[j])
		if err != nil {
			return nil, fmt.Errorf("error deidentifying row %d, column %d (%s): %w",
				rowIndex, j, config.columnNames[j], err)
		}

		resultRow[j] = deidentifiedValue
	}

	return resultRow, nil
}

// processSpecialAddressPattern handles a single special address pattern
func (d *Deidentifier) processSpecialAddressPattern(text, pattern string) string {
	regex := regexp.MustCompile(pattern)
	return regex.ReplaceAllStringFunc(text, func(addr string) string {
		deidentified, err := d.deidentifyValue(addr, TypeAddress, "address")
		if err != nil {
			return "[ADDRESS REDACTION ERROR]"
		}
		return deidentified
	})
}

// processSpecialAddressPattern3 handles special address pattern 3 with prefix handling
func (d *Deidentifier) processSpecialAddressPattern3(text string) string {
	specialAddr3Regex := regexp.MustCompile(specialAddressPattern3)
	return specialAddr3Regex.ReplaceAllStringFunc(text, func(addr string) string {
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
}

// processSpecialAddresses handles special address patterns
func (d *Deidentifier) processSpecialAddresses(text string) string {
	text = d.processSpecialAddressPattern(text, specialAddressPattern1)
	text = d.processSpecialAddressPattern(text, specialAddressPattern2)
	text = d.processSpecialAddressPattern3(text)
	return text
}

// processSSNMatch processes a single SSN match with validation
func (d *Deidentifier) processSSNMatch(ssn, originalText string) string {
	ssnHyphenRegex := regexp.MustCompile(ssnHyphenRegexPattern)
	ssnSpaceRegex := regexp.MustCompile(ssnSpaceRegexPattern)
	ssnContextRegex := regexp.MustCompile(ssnContextRegexPattern)

	rawDigits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(ssn, "")
	isFormatted := ssnHyphenRegex.MatchString(ssn) || ssnSpaceRegex.MatchString(ssn)
	hasSSNContext := ssnContextRegex.MatchString(originalText)

	if !isFormatted && !hasSSNContext && len(rawDigits) != 9 {
		return ssn
	}

	deidentified, err := d.deidentifyValue(ssn, TypeSSN, "ssn")
	if err != nil {
		return "[SSN REDACTION ERROR]"
	}
	return deidentified
}

// processSSNs handles SSN deidentification with context checking
func (d *Deidentifier) processSSNs(text, originalText string) string {
	ssnRegex := regexp.MustCompile(ssnRegexPattern)
	return ssnRegex.ReplaceAllStringFunc(text, func(ssn string) string {
		return d.processSSNMatch(ssn, originalText)
	})
}

// processStandardAddresses handles standard address patterns
func (d *Deidentifier) processStandardAddresses(text string) string {
	addrRegex := regexp.MustCompile(addressRegexPattern)
	return addrRegex.ReplaceAllStringFunc(text, func(addr string) string {
		deidentified, err := d.deidentifyValue(addr, TypeAddress, "address")
		if err != nil {
			return "[ADDRESS REDACTION ERROR]"
		}
		return deidentified
	})
}

// scoreColumnValues analyzes values in a column and updates type scores
func (d *Deidentifier) scoreColumnValues(data [][]string, col int, patterns *patternSet, typeScores map[DataType]int) int {
	sampleSize := len(data)
	if sampleSize > 10 {
		sampleSize = 10 // Sample first 10 rows for performance
	}

	validValues := 0
	for row := 0; row < sampleSize; row++ {
		if d.isValidValue(data, row, col) {
			value := strings.TrimSpace(data[row][col])
			validValues++
			d.scoreValue(value, patterns, typeScores)
		}
	}
	return validValues
}

// scoreValue scores a single value against all patterns
func (d *Deidentifier) scoreValue(value string, patterns *patternSet, typeScores map[DataType]int) {
	if patterns.email.MatchString(value) {
		typeScores[TypeEmail] += 10
	}
	if patterns.phone.MatchString(value) {
		typeScores[TypePhone] += 10
	}
	if patterns.ssn.MatchString(value) {
		typeScores[TypeSSN] += 10
	}
	if patterns.creditCard.MatchString(value) {
		typeScores[TypeCreditCard] += 10
	}
	if patterns.address.MatchString(value) || patterns.addressWord.MatchString(value) {
		typeScores[TypeAddress] += 10
	}
	if patterns.name.MatchString(value) && !patterns.addressWord.MatchString(value) {
		typeScores[TypeName] += 5 // Lower weight since names are harder to detect
	}
}

// selectBestType determines the best type based on scores and confidence thresholds
func (d *Deidentifier) selectBestType(typeScores map[DataType]int, validValues int) DataType {
	bestType, maxScore := d.findHighestScoringType(typeScores)

	if validValues == 0 {
		return TypeGeneric
	}

	threshold := d.getConfidenceThreshold(bestType, validValues)
	if maxScore >= threshold {
		return bestType
	}
	return TypeGeneric
}

// setDefaultColumnNames generates default column names if not provided
func (d *Deidentifier) setDefaultColumnNames(config *slicesConfig) error {
	if len(config.columnNames) == 0 {
		config.columnNames = make([]string, config.numCols)
		for i := 0; i < config.numCols; i++ {
			config.columnNames[i] = fmt.Sprintf("column_%d", i)
		}
	}
	return nil
}

// setMapping stores a mapping for deterministic results
func (d *Deidentifier) setMapping(columnName, original, replacement string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.mappingTables[columnName] == nil {
		d.mappingTables[columnName] = make(map[string]string)
	}
	d.mappingTables[columnName][original] = replacement
}

// validateSlicesConfig validates that configuration matches data structure
func (d *Deidentifier) validateSlicesConfig(config *slicesConfig) error {
	if len(config.columnTypes) != config.numCols || len(config.columnNames) != config.numCols {
		return fmt.Errorf("mismatch between data columns (%d) and provided column types (%d) or names (%d)",
			config.numCols, len(config.columnTypes), len(config.columnNames))
	}
	return nil
}

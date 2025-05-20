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

var (
	// Regular expression patterns for finding PII
	emailRegexPattern        = `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
	phoneRegexPattern        = `(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}`
	ssnRegexPattern          = `\d{3}[-]?\d{2}[-]?\d{4}`
	hyphenRegexPattern       = `-`
	ssnContextRegexPattern   = `(?i)SSN|social security`
	creditCardRegexPattern   = `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
	nameRegexPattern         = `\b[A-Z][a-z]+ [A-Z][a-z]+\b`
	addressWordRegexPattern  = `(?i)Street|Avenue|Road|Lane|The `
	addressRegexPattern      = `\d+\s+[A-Za-z]+ (Street|Avenue|Road|Drive|Lane|Place|Blvd|Boulevard)`
	phoneFormatRegexPattern  = `^(\+?1?\s?)?(\(?)(\d{3})(\)?[\s.-]?)(\d{3})([\s.-]?)(\d{4})`
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
		hyphenRegex := regexp.MustCompile(hyphenRegexPattern)
		ssnContextRegex := regexp.MustCompile(ssnContextRegexPattern)
		
		if !hyphenRegex.MatchString(ssn) && !ssnContextRegex.MatchString(text) {
			// If no hyphens and not mentioned as SSN, might be something else - check surrounding text
			if len(ssn) == 9 {
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

	// Process names (more complex, less precise)
	// This is a simplistic approach - production systems would use NER models
	nameRegex := regexp.MustCompile(nameRegexPattern)
	result = nameRegex.ReplaceAllStringFunc(result, func(name string) string {
		// Skip if it looks like an address or contains common words
		addressWordRegex := regexp.MustCompile(addressWordRegexPattern)
		if addressWordRegex.MatchString(name) {
			return name
		}
		deidentified, err := d.deidentifyValue(name, TypeName, "name")
		if err != nil {
			return "[NAME REDACTION ERROR]"
		}
		return deidentified
	})

	// Process addresses (simplified approach)
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
	return d.deidentifyValue(address, TypeAddress, "address")
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
	
	prefix := matches[1]         // +1 or country code (preserve)
	openParen := matches[2]      // ( or empty (preserve)
	areaCode := matches[3]       // 3 digits area code (preserve)
	afterAreaCode := matches[4]  // ) or . or - or space or empty (preserve)
	_ = matches[5]               // exchange - will be replaced
	separator := matches[6]      // . or - or space (preserve)
	_ = matches[7]               // last 4 digits - will be replaced
	
	hash := d.deterministicHash(original)
	exchange := 200 + d.hashToIndex(hash[:8], 799) // Valid exchange range
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
	
	group := 1 + d.hashToIndex(hash[8:16], 99)   // 01-99
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

// GenerateSecretKey generates a cryptographically secure random key
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
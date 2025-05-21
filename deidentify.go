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

var (
	// Regular expression patterns for finding PII
	emailRegexPattern               = `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
	phoneRegexPattern               = `(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}`
	ssnRegexPattern                 = `\d{3}[-]?\d{2}[-]?\d{4}`
	hyphenRegexPattern              = `-`
	ssnContextRegexPattern          = `(?i)SSN|social security`
	creditCardRegexPattern          = `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
	nameRegexPattern                = `\b[A-Z][a-z]+ [A-Z][a-z]+\b`
	addressWordRegexPattern         = `(?i)Street|Avenue|Road|Lane|Drive|Boulevard|Blvd|Way|Plaza|Square|Court|Terrace|Place|Circle|Alley|Row|Highway|Hwy|Parkway|Path|Trail|Crescent|Rue|Strasse|Straße|Calle|Via|Viale|Avenida|Carrer|Straat|Gasse|Weg|Camino|Ulica|Utca|Prospekt|Dori|Jalan|Marg|Dao|Jie|Lu`
	// Additional international address pattern for more precise name vs. address disambiguation
	internationalAddressRegexPattern = `(?i)(street|avenue|road|lane|drive|boulevard|blvd|way|plaza|square|court|terrace|place|circle|alley|row|highway|parkway|path|trail|crescent|rue|strasse|straße|calle|via|viale|avenida|carrer|straat|gasse|weg|camino|ulica|utca|prospekt|dori|jalan|marg|dao|jie|lu)`
	// Country and location patterns
	countryNameRegexPattern          = `(?i)(Afghanistan|Albania|Algeria|Andorra|Angola|Argentina|Armenia|Australia|Austria|Azerbaijan|Bahamas|Bahrain|Bangladesh|Barbados|Belarus|Belgium|Belize|Benin|Bhutan|Bolivia|Bosnia|Brazil|Brunei|Bulgaria|Burkina\s+Faso|Burundi|Cambodia|Cameroon|Canada|Chad|Chile|China|Colombia|Comoros|Congo|Costa\s+Rica|Croatia|Cuba|Cyprus|Czech|Denmark|Djibouti|Dominica|Dominican\s+Republic|Ecuador|Egypt|El\s+Salvador|Eritrea|Estonia|Eswatini|Ethiopia|Fiji|Finland|France|Gabon|Gambia|Georgia|Germany|Ghana|Greece|Grenada|Guatemala|Guinea|Guyana|Haiti|Honduras|Hungary|Iceland|India|Indonesia|Iran|Iraq|Ireland|Israel|Italy|Jamaica|Japan|Jordan|Kazakhstan|Kenya|Kiribati|Korea|Kuwait|Kyrgyzstan|Laos|Latvia|Lebanon|Lesotho|Liberia|Libya|Liechtenstein|Lithuania|Luxembourg|Madagascar|Malawi|Malaysia|Maldives|Mali|Malta|Mauritania|Mauritius|Mexico|Micronesia|Moldova|Monaco|Mongolia|Montenegro|Morocco|Mozambique|Myanmar|Namibia|Nauru|Nepal|Netherlands|New\s+Zealand|Nicaragua|Niger|Nigeria|Norway|Oman|Pakistan|Palau|Panama|Papua\s+New\s+Guinea|Paraguay|Peru|Philippines|Poland|Portugal|Qatar|Romania|Russia|Rwanda|Samoa|San\s+Marino|Saudi\s+Arabia|Senegal|Serbia|Seychelles|Sierra\s+Leone|Singapore|Slovakia|Slovenia|Solomon\s+Islands|Somalia|South\s+Africa|South\s+Sudan|Spain|Sri\s+Lanka|Sudan|Suriname|Sweden|Switzerland|Syria|Taiwan|Tajikistan|Tanzania|Thailand|Togo|Tonga|Trinidad\s+and\s+Tobago|Tunisia|Turkey|Turkmenistan|Tuvalu|Uganda|Ukraine|United\s+Arab\s+Emirates|UAE|United\s+Kingdom|UK|Great\s+Britain|Britain|England|Scotland|Wales|United\s+States|USA|U\.S\.A\.|U\.S\.|US|America|Uruguay|Uzbekistan|Vanuatu|Vatican|Venezuela|Vietnam|Yemen|Zambia|Zimbabwe)`
	cityRegexPattern                 = `(?i)(New\s+York|Los\s+Angeles|Chicago|Houston|Phoenix|Philadelphia|San\s+Antonio|San\s+Diego|Dallas|San\s+Jose|Austin|Jacksonville|Fort\s+Worth|Columbus|Charlotte|Indianapolis|San\s+Francisco|Seattle|Denver|Washington|Boston|London|Manchester|Birmingham|Liverpool|Glasgow|Edinburgh|Paris|Marseille|Lyon|Berlin|Munich|Hamburg|Frankfurt|Tokyo|Osaka|Kyoto|Seoul|Mumbai|Delhi|Hyderabad|Bangkok|Beijing|Shanghai|Hong\s+Kong|Singapore|Toronto|Vancouver|Montreal|Sydney|Melbourne|Brisbane|Madrid|Barcelona|Rome|Milan|Amsterdam|Brussels|Vienna|Prague|Moscow|St\.\s+Petersburg|Dubai|Abu\s+Dhabi|Riyadh|Cairo|Nairobi|Lagos|Johannesburg|Cape\s+Town|Casablanca|Istanbul|Ankara|Tehran|Baghdad|Karachi|Lahore|Dhaka|Jakarta|Manila|Auckland)`
	// ISO country code pattern 
	isoCountryCodeRegexPattern       = `(?i)\b(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|USA|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW)\b`
	
	// Special address patterns for international addresses with country names or ISO codes
	specialAddressPattern1 = `(?i)(\d+[-\s]?\w*|\d+-\d+-\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Road|Rd|Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr)[\s,]+` + countryNameRegexPattern
	specialAddressPattern2 = `(?i)(\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Rue|Via|Road|Street|Avenue)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*)[\s,]+` + cityRegexPattern + `[\s,]+` + countryNameRegexPattern
	// For addresses in text that might have a label before them (like "European HQ: 15 Rue de Rivoli")
	specialAddressPattern3 = `(?i)(:\s+|at\s+|@\s+)(\d+[-\s]?\w*|\d+-\d+-\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Road|Rd|Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Place|Pl|Rue|Via|Viale|Strasse|Straße|Calle|Avenida)`
	
	// Main address pattern to capture common formats across multiple countries
	addressRegexPattern              = `(?i)(\d+[-\s]?\w*|\d+-\d+-\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Place|Pl|Boulevard|Blvd|Way|Plaza|Square|Sq|Court|Ct|Terrace|Ter|Circle|Cir|Alley|Row|Highway|Hwy|Parkway|Pkwy|Path|Trail|Tr|Crescent|Cres|Rue|Strasse|Straße|Calle|Via|Viale|Avenida|Carrer|Straat|Gasse|Weg|Camino|Ulica|Utca|Prospekt|Dori|Jalan|Marg|Dao|Jie|Lu|út|de la|del|di|van|von)(\s*,\s*|\s+)([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*)?(\s*,\s*|\s+)?(` + isoCountryCodeRegexPattern + `|` + countryNameRegexPattern + `)?`
	phoneFormatRegexPattern          = `^(\+?1?\s?)?(\(?)(\d{3})(\)?[\s.-]?)(\d{3})([\s.-]?)(\d{4})`
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
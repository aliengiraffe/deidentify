package deidentify

// Regular expression patterns for finding PII
var (
	// Email pattern
	emailRegexPattern = `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`

	// Phone patterns
	phoneRegexPattern       = `(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}`
	phoneFormatRegexPattern = `^(\+?1?\s?)?(\(?)(\d{3})(\)?[\s.-]?)(\d{3})([\s.-]?)(\d{4})`

	// SSN patterns
	ssnRegexPattern        = `\d{3}[- ]?\d{2}[- ]?\d{4}`
	ssnSpaceRegexPattern   = `[ ]`
	ssnHyphenRegexPattern  = `[-]`
	ssnContextRegexPattern = `(?i)SSN|social security`

	// Credit card pattern
	creditCardRegexPattern = `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`

	// Name pattern
	nameRegexPattern = `\b[A-Z][a-z]+ [A-Z][a-z]+\b`

	// Address patterns
	addressWordRegexPattern = `(?i)\b(Street|Avenue|Road|Lane|Drive|Boulevard|Blvd|Way|Plaza|Square|Court|Terrace|Place|Circle|Alley|Row|Highway|Hwy|Parkway|Path|Trail|Crescent|Rue|Strasse|Straße|Calle|Via|Viale|Avenida|Carrer|Straat|Gasse|Weg|Camino|Ulica|Utca|Prospekt|Dori|Jalan|Marg|Dao|Jie|Lu)\b`

	// Additional international address pattern for more precise name vs. address disambiguation
	internationalAddressRegexPattern = `(?i)(street|avenue|road|lane|drive|boulevard|blvd|way|plaza|square|court|terrace|place|circle|alley|row|highway|parkway|path|trail|crescent|rue|strasse|straße|calle|via|viale|avenida|carrer|straat|gasse|weg|camino|ulica|utca|prospekt|dori|jalan|marg|dao|jie|lu)`

	// Country and location patterns
	countryNameRegexPattern = `(?i)(Afghanistan|Albania|Algeria|Andorra|Angola|Argentina|Armenia|Australia|Austria|Azerbaijan|Bahamas|Bahrain|Bangladesh|Barbados|Belarus|Belgium|Belize|Benin|Bhutan|Bolivia|Bosnia|Brazil|Brunei|Bulgaria|Burkina\s+Faso|Burundi|Cambodia|Cameroon|Canada|Chad|Chile|China|Colombia|Comoros|Congo|Costa\s+Rica|Croatia|Cuba|Cyprus|Czech|Denmark|Djibouti|Dominica|Dominican\s+Republic|Ecuador|Egypt|El\s+Salvador|Eritrea|Estonia|Eswatini|Ethiopia|Fiji|Finland|France|Gabon|Gambia|Georgia|Germany|Ghana|Greece|Grenada|Guatemala|Guinea|Guyana|Haiti|Honduras|Hungary|Iceland|India|Indonesia|Iran|Iraq|Ireland|Israel|Italy|Jamaica|Japan|Jordan|Kazakhstan|Kenya|Kiribati|Korea|Kuwait|Kyrgyzstan|Laos|Latvia|Lebanon|Lesotho|Liberia|Libya|Liechtenstein|Lithuania|Luxembourg|Madagascar|Malawi|Malaysia|Maldives|Mali|Malta|Mauritania|Mauritius|Mexico|Micronesia|Moldova|Monaco|Mongolia|Montenegro|Morocco|Mozambique|Myanmar|Namibia|Nauru|Nepal|Netherlands|New\s+Zealand|Nicaragua|Niger|Nigeria|Norway|Oman|Pakistan|Palau|Panama|Papua\s+New\s+Guinea|Paraguay|Peru|Philippines|Poland|Portugal|Qatar|Romania|Russia|Rwanda|Samoa|San\s+Marino|Saudi\s+Arabia|Senegal|Serbia|Seychelles|Sierra\s+Leone|Singapore|Slovakia|Slovenia|Solomon\s+Islands|Somalia|South\s+Africa|South\s+Sudan|Spain|Sri\s+Lanka|Sudan|Suriname|Sweden|Switzerland|Syria|Taiwan|Tajikistan|Tanzania|Thailand|Togo|Tonga|Trinidad\s+and\s+Tobago|Tunisia|Turkey|Turkmenistan|Tuvalu|Uganda|Ukraine|United\s+Arab\s+Emirates|UAE|United\s+Kingdom|UK|Great\s+Britain|Britain|England|Scotland|Wales|United\s+States|USA|U\.S\.A\.|U\.S\.|US|America|Uruguay|Uzbekistan|Vanuatu|Vatican|Venezuela|Vietnam|Yemen|Zambia|Zimbabwe)`

	cityRegexPattern = `(?i)(New\s+York|Los\s+Angeles|Chicago|Houston|Phoenix|Philadelphia|San\s+Antonio|San\s+Diego|Dallas|San\s+Jose|Austin|Jacksonville|Fort\s+Worth|Columbus|Charlotte|Indianapolis|San\s+Francisco|Seattle|Denver|Washington|Boston|London|Manchester|Birmingham|Liverpool|Glasgow|Edinburgh|Paris|Marseille|Lyon|Berlin|Munich|Hamburg|Frankfurt|Tokyo|Osaka|Kyoto|Seoul|Mumbai|Delhi|Hyderabad|Bangkok|Beijing|Shanghai|Hong\s+Kong|Singapore|Toronto|Vancouver|Montreal|Sydney|Melbourne|Brisbane|Madrid|Barcelona|Rome|Milan|Amsterdam|Brussels|Vienna|Prague|Moscow|St\.\s+Petersburg|Dubai|Abu\s+Dhabi|Riyadh|Cairo|Nairobi|Lagos|Johannesburg|Cape\s+Town|Casablanca|Istanbul|Ankara|Tehran|Baghdad|Karachi|Lahore|Dhaka|Jakarta|Manila|Auckland)`

	// ISO country code pattern
	isoCountryCodeRegexPattern = `(?i)\b(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|USA|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW)\b`

	// Special address patterns for international addresses with country names or ISO codes
	specialAddressPattern1 = `(?i)(\d+[-\s]?\w*|\d+-\d+-\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Road|Rd|Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr)[\s,]+` + countryNameRegexPattern

	specialAddressPattern2 = `(?i)(\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Rue|Via|Road|Street|Avenue)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*)[\s,]+` + cityRegexPattern + `[\s,]+` + countryNameRegexPattern

	// For addresses in text that might have a label before them (like "European HQ: 15 Rue de Rivoli")
	specialAddressPattern3 = `(?i)(:\s+|at\s+|@\s+)(\d+[-\s]?\w*|\d+-\d+-\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Road|Rd|Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Place|Pl|Rue|Via|Viale|Strasse|Straße|Calle|Avenida)`

	// Main address pattern to capture common formats across multiple countries
	addressRegexPattern = `(?i)(\d+[-\s]?\w*|\d+-\d+-\d+)[\s,]+([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*[\s,]+)+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Place|Pl|Boulevard|Blvd|Way|Plaza|Square|Sq|Court|Ct|Terrace|Ter|Circle|Cir|Alley|Row|Highway|Hwy|Parkway|Pkwy|Path|Trail|Tr|Crescent|Cres|Rue|Strasse|Straße|Calle|Via|Viale|Avenida|Carrer|Straat|Gasse|Weg|Camino|Ulica|Utca|Prospekt|Dori|Jalan|Marg|Dao|Jie|Lu|út|de la|del|di|van|von)(\s*,\s*|\s+)([A-Za-z\p{L}]+([\s'-][A-Za-z\p{L}]+)*)?(\s*,\s*|\s+)?(` + isoCountryCodeRegexPattern + `|` + countryNameRegexPattern + `)?`
)

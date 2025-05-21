package deidentify

// String lists for data generation
var (
	// Names for generating anonymous identities (100+ options)
	firstNameOptions = []string{
		"Alex", "Jordan", "Taylor", "Casey", "Morgan", "Riley", "Avery", "Quinn", "Sage", "Blake",
		"Jamie", "Dakota", "Charlie", "Hayden", "Emerson", "Rowan", "Parker", "Cameron", "Finley", "Drew",
		"River", "Skyler", "Peyton", "Reese", "Kendall", "Logan", "Robin", "Jesse", "Harley", "Dallas",
		"Remy", "Scout", "Shawn", "Devon", "Kelly", "Adrian", "Jackie", "Angel", "Leslie", "Justice",
		"Sydney", "Elliott", "Addison", "Kai", "Marley", "Shannon", "Ali", "Zion", "Phoenix", "Eden",
		"Harper", "Sawyer", "Micah", "Jules", "Spencer", "Jayden", "Ashton", "Luca", "Kerry", "Avery",
		"Erin", "Shane", "Marlow", "Austin", "Rory", "Lennon", "Jaden", "Jude", "Nova", "Noel",
		"Kennedy", "Shay", "Laine", "Kris", "Frankie", "Haven", "Gray", "Amari", "Sasha", "Lennox",
		"Tatum", "Izzy", "Winter", "Cassidy", "Pat", "Keegan", "Lyric", "Blair", "Briar", "Ellis",
		"Oakley", "Shiloh", "Salem", "Sutton", "Arden", "Cypress", "Lee", "Finley", "Wren", "Bellamy",
		"Billie", "Armani", "Jaime", "Storm", "Alva", "Rio", "Marlo", "Milan", "Sidney", "Royal",
		"Ronnie", "Sky", "Jett", "Remi", "Kit", "Perry", "Lake", "Sol", "Oak", "Mica",
	}

	lastNameOptions = []string{
		"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
		"Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
		"Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
		"Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
		"Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
		"Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes",
		"Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper",
		"Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
		"Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
		"Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez",
		"Powell", "Jenkins", "Perry", "Russell", "Sullivan", "Bell", "Coleman", "Butler", "Henderson", "Barnes",
		"Gonzales", "Fisher", "Vasquez", "Simmons", "Romero", "Jordan", "Patterson", "Alexander", "Hamilton", "Graham",
		"Reynolds", "Griffin", "Wallace", "Moreno", "West", "Cole", "Hayes", "Bryant", "Herrera", "Gibson",
	}

	// Email data for generating anonymous emails (100+ options)
	emailDomainOptions = []string{
		"example.com", "testmail.org", "sample.net", "demo.co", "placeholder.io", "test.com", "acme.org", "mail.net",
		"noreply.co", "company.io", "secure.net", "private.email", "mock.com", "temporary.org", "proxy.net",
		"anon.co", "redacted.io", "pseudo.com", "example.org", "example.net", "example.io", "test.org", "test.net",
		"test.io", "sample.org", "sample.io", "demo.org", "demo.net", "placeholder.org", "placeholder.net",
		"acme.com", "acme.net", "acme.io", "mail.com", "mail.org", "mail.io", "noreply.com", "noreply.org",
		"noreply.net", "company.com", "company.org", "company.net", "secure.com", "secure.org", "secure.io",
		"private.com", "private.org", "private.net", "mock.org", "mock.net", "mock.io", "temporary.com",
		"temporary.net", "temporary.io", "proxy.com", "proxy.org", "proxy.io", "anon.com", "anon.org", "anon.net",
		"redacted.com", "redacted.org", "redacted.net", "pseudo.org", "pseudo.net", "pseudo.io", "dummy.com",
		"dummy.org", "dummy.net", "dummy.io", "invalid.com", "invalid.org", "invalid.net", "invalid.io",
		"nowhere.com", "nowhere.org", "nowhere.net", "nowhere.io", "null.com", "null.org", "null.net", "null.io",
		"void.com", "void.org", "void.net", "void.io", "empty.com", "empty.org", "empty.net", "empty.io",
		"masked.com", "masked.org", "masked.net", "masked.io", "hidden.com", "hidden.org", "hidden.net", "hidden.io",
		"anonymous.com", "anonymous.org", "anonymous.net", "anonymous.io", "privacy.com", "privacy.org", "privacy.net",
	}

	emailUsernameOptions = []string{
		"user", "test", "demo", "sample", "client", "member", "account", "profile", "person", "contact",
		"info", "support", "admin", "help", "service", "mail", "email", "inbox", "webmaster", "customer",
		"guest", "anonymous", "user123", "tester", "demouser", "testuser", "newuser", "tempuser", "randomuser", "sampleuser",
		"clientuser", "memberuser", "accountuser", "profileuser", "personuser", "contactuser", "infouser", "supportuser", "adminuser", "helpuser",
		"serviceuser", "mailuser", "emailuser", "inboxuser", "webmasteruser", "customeruser", "guestuser", "anonymoususer", "example", "noreply",
		"donotreply", "no-reply", "feedback", "hello", "hi", "notification", "alerts", "system", "automate", "bot",
		"robot", "data", "testdata", "sampledata", "mockdata", "fakedata", "placeholder", "temp", "temporary", "disposable",
		"dummy", "null", "void", "none", "empty", "blank", "zero", "nil", "undefined", "default",
		"standard", "generic", "common", "normal", "typical", "regular", "routine", "ordinary", "usual", "customary",
		"general", "universal", "global", "worldwide", "international", "national", "regional", "local", "personal", "individual",
		"private", "public", "shared", "common", "mutual", "joint", "collective", "combined", "merged", "unified",
	}

	// Address data for generating anonymous addresses (120+ options with international variety)
	streetNameOptions = []string{
		// English/American/Canadian patterns
		"Main St", "Oak Ave", "Pine Rd", "Elm Way", "Park Blvd", "First St", "Second Ave", "Third Rd", "Fourth St", "Fifth Ave",
		"Maple Dr", "Cedar Ln", "Walnut St", "Cherry Ave", "Washington Blvd", "Lincoln Rd", "Jefferson St", "Adams Ave", "Madison Dr", "Jackson Blvd",
		"Highland Ave", "Valley Rd", "Forest Dr", "Meadow Ln", "River St", "Lake Ave", "Sunset Blvd", "Sunrise Dr", "Hill Rd", "Mountain View Ave",
		"Spring St", "Summer Rd", "Autumn Ave", "Winter Dr", "North St", "South Ave", "East Rd", "West Blvd", "Central Dr", "Union St",
		"Division Ave", "Grove Rd", "Spruce St", "Willow Ave", "Hickory Dr", "Birch Ln", "Sycamore St", "Poplar Ave", "Aspen Rd", "Cypress Dr",
		"Lakeview St", "Hillside Ave", "Summit Rd", "Ridge Dr", "Highland Park Ave", "Crescent St", "Woodland Rd", "Meadowlark Ln", "Colonial Dr", "Heritage Ave",
		"Liberty St", "Freedom Rd", "Independence Ave", "Victory Dr", "Patriot St", "Pioneer Rd", "Frontier Ave", "Homestead Dr", "Prairie St", "Plains Rd",
		"Desert Ave", "Ocean Dr", "Beach St", "Shore Rd", "Bay Ave", "Harbor Dr", "Port St", "Dock Rd", "Marina Ave", "Lighthouse Dr",
		"Beacon St", "College Rd", "University Ave", "Campus Dr", "School St", "Academy Rd", "Church Ave", "Chapel Dr", "Temple St", "Seminary Rd",
		"Market Ave", "Commerce Dr", "Business St", "Industry Rd", "Corporate Ave", "Office Dr", "Plaza St", "Center Rd", "Town Square", "Village Green",
		"Garden St", "Orchard Rd", "Farm Ave", "Ranch Dr", "Estate St", "Manor Rd", "Castle Ave", "Palace Dr", "Royal St", "Crown Rd",
		// European patterns
		"Rue de la Paix", "Avenue des Champs-Élysées", "Via Roma", "Calle Mayor", "Königstraße", "Hauptstraße",
		"High Street", "Baker Street", "Oxford Street", "Strand", "Gran Vía", "Passeig de Gràcia",
		// Asian patterns
		"Chang'an Avenue", "Nanjing Road", "Orchard Road", "Shinjuku Dori", "Ginza Dori", "Sukhumvit Road",
		// Global/International
		"Plaza Mayor", "Via Veneto", "Friedrichstraße", "Bond Street", "Broadway", "Champs-Élysées",
		"Sheikh Zayed Road", "Las Ramblas", "Nevsky Prospekt", "Puerta del Sol", "Andrássy Avenue", "Khao San Road",
	}
)

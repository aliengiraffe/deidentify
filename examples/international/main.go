package main

import (
	"fmt"
	"log"

	"github.com/aliengiraffe/deidentify"
)

func main() {
	// Generate a secure secret key
	secretKey, err := deidentify.GenerateSecretKey()
	if err != nil {
		log.Fatal("Failed to generate secret key:", err)
	}

	// Create a new deidentifier with default options
	d := deidentify.NewDeidentifier(secretKey)

	// Sample international addresses
	addresses := []string{
		"123 Main Street, Springfield, IL",           // US
		"10 Downing Street, London, UK",              // UK
		"1600 Pennsylvania Avenue, Washington DC",    // US
		"221B Baker Street, London, UK",              // UK (famous)
		"42 Rue de la Paix, Paris, France",           // France
		"1234 Calle Mayor, Madrid, Spain",            // Spain
		"56 Via Roma, Rome, Italy",                   // Italy
		"789 Königstraße, Berlin, Germany",           // Germany
		"5-1-5 Ginza, Chuo-ku, Tokyo, Japan",         // Japan
		"888 Nanjing Road, Shanghai, China",          // China
		"27 Sheikh Zayed Road, Dubai, UAE",           // UAE
		"45 Sukhumvit Road, Bangkok, Thailand",       // Thailand
		"33 Nevsky Prospekt, St. Petersburg, Russia", // Russia
		"17 Andrássy út, Budapest, Hungary",          // Hungary
	}

	// Process and display
	fmt.Println("International Address Detection and Deidentification")
	fmt.Println("===================================================")
	fmt.Println()

	// Special focus on our problematic examples
	fmt.Println("FOCUS ON SPECIFIC EXAMPLES:")
	fmt.Println("---------------------------")
	specificExamples := []string{
		"123 Orchard Road, Singapore",
		"15 Rue de Rivoli, Paris, France",
	}

	for _, address := range specificExamples {
		redacted, err := d.DeidentifyAddress(address)
		if err != nil {
			fmt.Printf("Error processing '%s': %v\n", address, err)
			continue
		}

		fmt.Printf("Original: %s\n", address)
		fmt.Printf("Redacted: %s\n\n", redacted)
	}

	fmt.Println("OTHER INTERNATIONAL EXAMPLES:")
	fmt.Println("----------------------------")
	for _, address := range addresses {
		redacted, err := d.DeidentifyAddress(address)
		if err != nil {
			fmt.Printf("Error processing '%s': %v\n", address, err)
			continue
		}

		fmt.Printf("Original: %s\n", address)
		fmt.Printf("Redacted: %s\n\n", redacted)
	}

	// Sample text with international addresses - focusing on the specific examples
	text := `Our company has offices at multiple locations:
- European HQ: 15 Rue de Rivoli, Paris, France (this is our main office)
- Asian HQ: 123 Orchard Road, Singapore
- North American HQ: 555 Fifth Avenue, New York, NY
- Middle Eastern office: 78 Sheikh Zayed Road, Dubai, UAE
Please contact us at contact@example.com or call our main line at (555) 123-4567.`

	// Process the text
	fmt.Println("Text with International Addresses")
	fmt.Println("================================")
	fmt.Println("Original:")
	fmt.Println(text)
	fmt.Println()

	redactedText, err := d.DeidentifyText(text)
	if err != nil {
		log.Fatal("Failed to deidentify text:", err)
	}

	fmt.Println("Redacted:")
	fmt.Println(redactedText)
}

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

	// Example text containing various PII
	text := `From: Legolas Greenleaf <legolas@mirkwood.elf>
To: White Council Support
Subject: Ring Information

Hello,

My name is Legolas Greenleaf and I need help with my quest. 
My phone number is (555) 123-4567 and my SSN is 123-45-6789.
My friend's social security number is 123 45 6789 and my assistant's SSN is 987654321.
I made a payment using my credit card 4111-1111-1111-1111 yesterday.

I live at 15 Woodland Realm, Mirkwood Forest, Middle-earth.

Thanks,
Legolas`

	// Simple deidentification
	redacted, err := d.Text(text)
	if err != nil {
		log.Fatal("Failed to deidentify text:", err)
	}

	fmt.Println("Original text:")
	fmt.Println("--------------------------------------")
	fmt.Println(text)
	fmt.Println("\nDeidentified text:")
	fmt.Println("--------------------------------------")
	fmt.Println(redacted)

	// Demonstrate type-specific deidentification
	fmt.Println("\nType-specific deidentification:")
	fmt.Println("--------------------------------------")

	email := "legolas@mirkwood.elf"
	redactedEmail, err := d.Email(email)
	if err != nil {
		log.Fatal("Failed to deidentify email:", err)
	}
	fmt.Printf("Email: %s → %s\n", email, redactedEmail)

	phone := "(555) 123-4567"
	redactedPhone, err := d.Phone(phone)
	if err != nil {
		log.Fatal("Failed to deidentify phone:", err)
	}
	fmt.Printf("Phone: %s → %s\n", phone, redactedPhone)

	// Test different SSN formats
	ssnFormats := []string{
		"123-45-6789", // With hyphens
		"123 45 6789", // With spaces
		"123456789",   // Without separators
	}

	for _, ssn := range ssnFormats {
		redactedSSN, err := d.SSN(ssn)
		if err != nil {
			log.Fatal("Failed to deidentify SSN:", err)
		}
		fmt.Printf("SSN: %s → %s\n", ssn, redactedSSN)
	}

	address := "15 Woodland Realm, Mirkwood Forest"
	redactedAddress, err := d.Address(address)
	if err != nil {
		log.Fatal("Failed to deidentify address:", err)
	}
	fmt.Printf("Address: %s → %s\n", address, redactedAddress)

	name := "Legolas Greenleaf"
	redactedName, err := d.Name(name)
	if err != nil {
		log.Fatal("Failed to deidentify name:", err)
	}
	fmt.Printf("Name: %s → %s\n", name, redactedName)

	// Demonstrating consistency - same input produces same output
	fmt.Println("\nConsistency demonstration:")
	fmt.Println("--------------------------------------")
	anotherEmail := "legolas@mirkwood.elf" // Same email as before
	redactedAgain, _ := d.Email(anotherEmail)
	fmt.Printf("Same input produces same output: %v\n",
		redactedEmail == redactedAgain)

	// Demonstrate the variety of generated values
	fmt.Println("\nDemonstrating data variety:")
	fmt.Println("--------------------------------------")

	// Create another deidentifier with a different key
	d2 := deidentify.NewDeidentifier("different-secret-key")

	fmt.Println("Names:")
	for i := 0; i < 5; i++ {
		sampleName := fmt.Sprintf("Sample Person %d", i)
		redacted, _ := d2.Name(sampleName)
		fmt.Printf("  %s → %s\n", sampleName, redacted)
	}

	fmt.Println("\nEmails:")
	for i := 0; i < 5; i++ {
		sampleEmail := fmt.Sprintf("person%d@example.com", i)
		redacted, _ := d2.Email(sampleEmail)
		fmt.Printf("  %s → %s\n", sampleEmail, redacted)
	}

	fmt.Println("\nAddresses:")
	for i := 0; i < 5; i++ {
		sampleAddress := fmt.Sprintf("%d Example Street", 100+i)
		redacted, _ := d2.Address(sampleAddress)
		fmt.Printf("  %s → %s\n", sampleAddress, redacted)
	}
}

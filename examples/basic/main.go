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
	text := `From: John Smith <john.smith@example.com>
To: Customer Support
Subject: Account Information

Hello,

My name is John Smith and I need help with my account. 
My phone number is (555) 123-4567 and my SSN is 123-45-6789.
I made a payment using my credit card 4111-1111-1111-1111 yesterday.

I live at 123 Main Street, New York, NY 10001.

Thanks,
John`

	// Simple deidentification
	redacted, err := d.DeidentifyText(text)
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
	
	email := "john.smith@example.com"
	redactedEmail, err := d.DeidentifyEmail(email)
	if err != nil {
		log.Fatal("Failed to deidentify email:", err)
	}
	fmt.Printf("Email: %s → %s\n", email, redactedEmail)
	
	phone := "(555) 123-4567"
	redactedPhone, err := d.DeidentifyPhone(phone)
	if err != nil {
		log.Fatal("Failed to deidentify phone:", err)
	}
	fmt.Printf("Phone: %s → %s\n", phone, redactedPhone)
	
	ssn := "123-45-6789"
	redactedSSN, err := d.DeidentifySSN(ssn)
	if err != nil {
		log.Fatal("Failed to deidentify SSN:", err)
	}
	fmt.Printf("SSN: %s → %s\n", ssn, redactedSSN)
	
	// Demonstrating consistency - same input produces same output
	fmt.Println("\nConsistency demonstration:")
	fmt.Println("--------------------------------------")
	anotherEmail := "john.smith@example.com" // Same email as before
	redactedAgain, _ := d.DeidentifyEmail(anotherEmail)
	fmt.Printf("Same input produces same output: %v\n", 
		redactedEmail == redactedAgain)
}
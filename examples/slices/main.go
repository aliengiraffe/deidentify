package main

import (
	"fmt"
	"log"
	"strings"
	
	"github.com/aliengiraffe/deidentify"
)

func main() {
	// Generate a secure secret key
	secretKey, err := deidentify.GenerateSecretKey()
	if err != nil {
		log.Fatal("Failed to generate secret key:", err)
	}
	
	// Create deidentifier
	d := deidentify.NewDeidentifier(secretKey)
	
	// Example CSV-like data as [][]string
	// This could come from reading a CSV file, database query, etc.
	customerData := [][]string{
		// Header row (optional - you can skip if not needed)
		{"Name", "Email", "Phone", "SSN", "Address"},
		// Data rows
		{"Alice Johnson", "alice.johnson@techcorp.com", "+1 (555) 123-4567", "123-45-6789", "123 Oak Street, Portland, OR"},
		{"Bob Smith", "bob.smith@example.org", "555-987-6543", "987-65-4321", "456 Pine Avenue, Seattle, WA"},
		{"Carol Davis", "carol@startup.io", "(555) 111-2222", "456-78-9012", "789 Maple Drive, San Francisco, CA"},
		{"", "", "", "", ""}, // Handle empty row
		{"David Wilson", "david.wilson@company.net", "555.333.4444", "321-54-9876", "321 Elm Street, Austin, TX"},
	}
	
	// Define column types (skip header row)
	columnTypes := []deidentify.DataType{
		deidentify.TypeName,
		deidentify.TypeEmail,
		deidentify.TypePhone,
		deidentify.TypeSSN,
		deidentify.TypeAddress,
	}
	
	// Define column names for consistent mapping
	columnNames := []string{
		"customer_name",
		"customer_email", 
		"customer_phone",
		"customer_ssn",
		"customer_address",
	}
	
	fmt.Println("Original Customer Data:")
	printSlices(customerData)
	
	// Extract data rows (skip header)
	dataRows := customerData[1:]
	
	// Deidentify the data
	deidentifiedData, err := d.DeidentifySlices(dataRows, columnTypes, columnNames)
	if err != nil {
		log.Fatal("Failed to deidentify data:", err)
	}
	
	// Reconstruct with header
	result := [][]string{customerData[0]} // Keep original header
	result = append(result, deidentifiedData...)
	
	fmt.Println("\nDeidentified Customer Data:")
	printSlices(result)
	
	// Demonstrate deterministic behavior
	fmt.Println("\n=== Deterministic Behavior Demo ===")
	
	// Same data processed again should produce identical results
	sampleRow := [][]string{{"Alice Johnson", "alice.johnson@techcorp.com", "+1 (555) 123-4567", "123-45-6789", "123 Oak Street, Portland, OR"}}
	result1, _ := d.DeidentifySlices(sampleRow, columnTypes, columnNames)
	result2, _ := d.DeidentifySlices(sampleRow, columnTypes, columnNames)
	
	fmt.Printf("First run:  %v\n", result1[0])
	fmt.Printf("Second run: %v\n", result2[0])
	fmt.Printf("Identical results: %t\n", equalSlices(result1[0], result2[0]))
	
	// Different column names produce different results
	fmt.Println("\n=== Column-Specific Mapping Demo ===")
	
	// Create new deidentifier for clean test
	d2 := deidentify.NewDeidentifier(secretKey)
	
	differentColumnNames := []string{
		"employee_name",     // Different from "customer_name"
		"employee_email",    // Different from "customer_email"  
		"employee_phone",    // Different from "customer_phone"
		"employee_ssn",      // Different from "customer_ssn"
		"employee_address",  // Different from "customer_address"
	}
	
	result3, _ := d2.DeidentifySlices(sampleRow, columnTypes, differentColumnNames)
	
	fmt.Printf("Customer context: %s\n", result1[0][0])
	fmt.Printf("Employee context: %s\n", result3[0][0])
	fmt.Printf("Different results: %t\n", result1[0][0] != result3[0][0])
	
	// Practical use case: Processing CSV-like data in batches
	fmt.Println("\n=== Batch Processing Demo ===")
	
	// Simulate processing data in chunks (useful for large datasets)
	allData := [][]string{
		{"John Doe", "john@example.com", "555-0001", "111-11-1111", "100 First St"},
		{"Jane Doe", "jane@example.com", "555-0002", "222-22-2222", "200 Second St"},
		{"Jim Doe", "jim@example.com", "555-0003", "333-33-3333", "300 Third St"},
	}
	
	batchSize := 2
	var processedBatches [][]string
	
	for i := 0; i < len(allData); i += batchSize {
		end := i + batchSize
		if end > len(allData) {
			end = len(allData)
		}
		
		batch := allData[i:end]
		deidentifiedBatch, err := d.DeidentifySlices(batch, columnTypes, columnNames)
		if err != nil {
			log.Printf("Error processing batch %d: %v", i/batchSize+1, err)
			continue
		}
		
		processedBatches = append(processedBatches, deidentifiedBatch...)
		fmt.Printf("Processed batch %d: %d rows\n", i/batchSize+1, len(deidentifiedBatch))
	}
	
	fmt.Printf("Total processed: %d rows\n", len(processedBatches))
}

func printSlices(data [][]string) {
	if len(data) == 0 {
		fmt.Println("(empty)")
		return
	}
	
	// Calculate column widths for nice formatting
	colWidths := make([]int, len(data[0]))
	for _, row := range data {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}
	
	// Ensure minimum width
	for i := range colWidths {
		if colWidths[i] < 15 {
			colWidths[i] = 15
		}
	}
	
	// Print header separator
	printSeparator(colWidths)
	
	// Print each row
	for i, row := range data {
		fmt.Print("| ")
		for j, cell := range row {
			if cell == "" {
				cell = "<empty>"
			}
			fmt.Printf("%-*s | ", colWidths[j], truncate(cell, colWidths[j]))
		}
		fmt.Println()
		
		// Print separator after header
		if i == 0 {
			printSeparator(colWidths)
		}
	}
	
	// Print footer separator
	printSeparator(colWidths)
}

func printSeparator(colWidths []int) {
	fmt.Print("+")
	for _, width := range colWidths {
		fmt.Print(strings.Repeat("-", width+2) + "+")
	}
	fmt.Println()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
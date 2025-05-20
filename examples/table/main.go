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
	
	// Create deidentifier
	d := deidentify.NewDeidentifier(secretKey)
	
	// Example table with mixed data types
	table := &deidentify.Table{
		Columns: []deidentify.Column{
			{
				Name:     "customer_name",
				DataType: deidentify.TypeName,
				Values: []interface{}{
					"Gandalf Grey",
					"Galadriel Lothlorien", 
					"Elrond Halfelven",
					nil, // Handle nil values
				},
			},
			{
				Name:     "email",
				DataType: deidentify.TypeEmail,
				Values: []interface{}{
					"mithrandir@istari.me",
					"lady@lothlorien.elf",
					"elrond@rivendell.me",
					"",
				},
			},
			{
				Name:     "phone",
				DataType: deidentify.TypePhone,
				Values: []interface{}{
					"+1 (555) 123-4567",
					"555-987-6543",
					"(444) 555 1234",
					nil,
				},
			},
			{
				Name:     "ssn",
				DataType: deidentify.TypeSSN,
				Values: []interface{}{
					"123-45-6789",
					"987-65-4321",
					"456-78-9012",
					"",
				},
			},
			{
				Name:     "credit_card",
				DataType: deidentify.TypeCreditCard,
				Values: []interface{}{
					"4532 1234 5678 9012",
					"4000-1111-2222-3333",
					"4111111111111111",
					nil,
				},
			},
			{
				Name:     "address",
				DataType: deidentify.TypeAddress,
				Values: []interface{}{
					"Grey Havens, Lindon",
					"Lothlorien Forest, Middle-earth",
					"Rivendell Valley, Eriador",
					"",
				},
			},
		},
	}
	
	fmt.Println("Original Data:")
	printTable(table)
	
	// Deidentify the table
	deidentifiedTable, err := d.DeidentifyTable(table)
	if err != nil {
		log.Fatal("Failed to deidentify table:", err)
	}
	
	fmt.Println("\nDeidentified Data:")
	printTable(deidentifiedTable)
	
	// Demonstrate deterministic behavior
	fmt.Println("\nDeterministic Test:")
	table2 := &deidentify.Table{
		Columns: []deidentify.Column{
			{
				Name:     "customer_name",
				DataType: deidentify.TypeName,
				Values:   []interface{}{"Gandalf Grey"}, // Same value as before
			},
		},
	}
	
	result2, _ := d.DeidentifyTable(table2)
	fmt.Printf("Same input 'Gandalf Grey' produces same output: %v\n", 
		result2.Columns[0].Values[0])
	
	// Demonstrate different column names produce different mappings
	table3 := &deidentify.Table{
		Columns: []deidentify.Column{
			{
				Name:     "wizard_name", // Different column name
				DataType: deidentify.TypeName,
				Values:   []interface{}{"Gandalf Grey"}, // Same value
			},
		},
	}
	
	result3, _ := d.DeidentifyTable(table3)
	fmt.Printf("Same input in different column produces different output: %v\n", 
		result3.Columns[0].Values[0])
}

func printTable(table *deidentify.Table) {
	// Print headers
	for _, col := range table.Columns {
		fmt.Printf("%-20s", col.Name)
	}
	fmt.Println()
	
	// Print separator
	for range table.Columns {
		fmt.Printf("%-20s", "--------------------")
	}
	fmt.Println()
	
	// Print data rows
	if len(table.Columns) > 0 {
		numRows := len(table.Columns[0].Values)
		for i := 0; i < numRows; i++ {
			for _, col := range table.Columns {
				value := col.Values[i]
				if value == nil {
					fmt.Printf("%-20s", "<nil>")
				} else {
					fmt.Printf("%-20s", fmt.Sprintf("%v", value))
				}
			}
			fmt.Println()
		}
	}
}
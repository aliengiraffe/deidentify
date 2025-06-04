package deidentify

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

// Sample paragraphs with various types of PII
var sampleParagraphs = []string{
	// Paragraph 1: Professional context with multiple PII types
	"John Smith works as a senior software engineer at TechCorp. He can be reached at john.smith@techcorp.com or by phone at (555) 123-4567. His social security number is 123-45-6789 and he lives at 123 Main Street, San Francisco, CA 94105. For urgent matters, you can also contact his manager Sarah Johnson at sarah.johnson@techcorp.com.",

	// Paragraph 2: Medical context
	"Patient Mary Williams (DOB: 01/15/1985, SSN: 987-65-4321) presented to Dr. Robert Chen at 456 Oak Avenue Medical Center on March 15, 2024. Her primary phone number is 555-987-6543 and emergency contact is her husband David Williams at (555) 321-9876. Insurance was billed using card number 4532 1234 5678 9012.",

	// Paragraph 3: Financial services
	"Dear Michael Brown, your account ending in 3456 has been approved. Please verify your identity using SSN 456-78-9012. We have your address on file as 789 Pine Street, New York, NY 10001. For questions, contact your advisor Jennifer Davis at jdavis@financialgroup.com or call 1-800-555-0123.",

	// Paragraph 4: Educational records
	"Student Elizabeth Taylor (ID: 234-56-7890) enrolled in Computer Science program. Contact: etaylor@university.edu, phone: (555) 234-5678. Permanent address: 321 College Drive, Boston, MA 02134. Emergency contact: Thomas Taylor at ttaylor@email.com, relationship: father.",

	// Paragraph 5: Customer service interaction
	"Thank you for contacting customer support, James Anderson. We have your account information: email james.anderson@email.com, phone 555.876.5432, and billing address at 567 Elm Street, Chicago, IL 60601. Your credit card ending in 5678 will be charged $99.99. Reference number: SSN-789-01-2345.",

	// Paragraph 6: Human resources document
	"Employee Profile: Patricia Martinez\nPosition: Marketing Director\nEmail: pmartinez@company.com\nDirect Line: (555) 345-6789\nSSN: 890-12-3456\nHome Address: 234 Broadway Avenue, Los Angeles, CA 90001\nEmergency Contact: Carlos Martinez (spouse) - 555-456-7890",

	// Paragraph 7: Legal document
	"This agreement is between Christopher Lee (SSN: 901-23-4567) residing at 890 Court Street, Houston, TX 77001, contact: chris.lee@lawfirm.com or (555) 567-8901, and Amanda White located at 123 Justice Lane, with email awhite@legal.net. Payment via credit card 5432 1098 7654 3210.",

	// Paragraph 8: Travel booking
	"Booking confirmation for Nancy Garcia: Flight AA123 on April 20, 2024. Passenger contact: ngarcia@travel.com, mobile: 555.789.0123. TSA PreCheck: 345-67-8901. Billing address: 456 Airport Road, Miami, FL 33101. Payment method: Visa ending in 8765.",

	// Paragraph 9: Real estate transaction
	"Property viewing scheduled for buyer Richard Thompson (rthompson@realty.com, 555-890-1234). Current address: 678 Market Street, Seattle, WA 98101. Pre-approval based on SSN 012-34-5678. Seller: Barbara Wilson at 789 Lake Drive, contact: (555) 098-7654.",

	// Paragraph 10: Insurance claim
	"Claim #12345 filed by Daniel Rodriguez, DOB: 05/20/1980, SSN: 123-45-6789. Contact information: drodriguez@insurance.com, (555) 210-9876. Incident location: 345 Accident Avenue, Phoenix, AZ 85001. Policy paid via credit card 4123 4567 8901 2345. Adjuster: Lisa Chen at lchen@insuranceco.com.",
}

// BenchmarkParagraphDeidentification benchmarks the deidentification of paragraphs containing PII
func BenchmarkParagraphDeidentification(b *testing.B) {
	d := NewDeidentifier("benchmark-secret-key")

	// Create a random generator with a fixed seed for reproducibility
	rng := rand.New(rand.NewSource(42))

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run the benchmark b.N times
	for i := 0; i < b.N; i++ {
		// Select a random paragraph
		paragraphIndex := rng.Intn(len(sampleParagraphs))
		paragraph := sampleParagraphs[paragraphIndex]

		// Deidentify the paragraph
		_, err := d.Text(paragraph)
		if err != nil {
			b.Fatalf("Deidentification failed: %v", err)
		}
	}
}

// BenchmarkParagraphDeidentificationParallel benchmarks parallel deidentification
func BenchmarkParagraphDeidentificationParallel(b *testing.B) {
	d := NewDeidentifier("benchmark-secret-key")

	b.RunParallel(func(pb *testing.PB) {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))

		for pb.Next() {
			// Select a random paragraph
			paragraphIndex := rng.Intn(len(sampleParagraphs))
			paragraph := sampleParagraphs[paragraphIndex]

			_, err := d.Text(paragraph)
			if err != nil {
				b.Fatalf("Deidentification failed: %v", err)
			}
		}
	})
}

// TestBenchmarkCorrectness verifies that the deidentification is working correctly
func TestBenchmarkCorrectness(t *testing.T) {
	d := NewDeidentifier("test-secret-key")

	// Test each sample paragraph to ensure PII is properly deidentified
	for i, paragraph := range sampleParagraphs {
		result, err := d.Text(paragraph)
		if err != nil {
			t.Fatalf("Failed to deidentify paragraph %d: %v", i, err)
		}

		// Check that common PII patterns are not present in the result
		// These are the original patterns that should NOT appear
		piiPatterns := []string{
			// Original emails from paragraphs
			"john.smith@techcorp.com",
			"sarah.johnson@techcorp.com",
			"jdavis@financialgroup.com",
			"etaylor@university.edu",
			"james.anderson@email.com",
			"pmartinez@company.com",
			"chris.lee@lawfirm.com",
			"awhite@legal.net",
			"ngarcia@travel.com",
			"rthompson@realty.com",
			"drodriguez@insurance.com",
			"lchen@insuranceco.com",
			// Original SSNs
			"123-45-6789",
			"987-65-4321",
			"456-78-9012",
			"234-56-7890",
			"789-01-2345",
			"890-12-3456",
			"901-23-4567",
			"345-67-8901",
			"012-34-5678",
			// Original phone numbers
			"(555) 123-4567",
			"555-987-6543",
			"(555) 321-9876",
			"1-800-555-0123",
			"555.876.5432",
			"(555) 345-6789",
			"555-456-7890",
			"(555) 567-8901",
			"555.789.0123",
			"555-890-1234",
			"(555) 098-7654",
			"(555) 210-9876",
			// Original credit cards
			"4532 1234 5678 9012",
			"5432 1098 7654 3210",
			"4123 4567 8901 2345",
			// Original addresses
			"123 Main Street",
			"456 Oak Avenue",
			"789 Pine Street",
			"321 College Drive",
			"567 Elm Street",
			"234 Broadway Avenue",
			"890 Court Street",
			"123 Justice Lane",
			"456 Airport Road",
			"678 Market Street",
			"789 Lake Drive",
			"345 Accident Avenue",
		}

		for _, pattern := range piiPatterns {
			if strings.Contains(result, pattern) {
				t.Errorf("Paragraph %d still contains PII: %s", i, pattern)
				t.Logf("Original: %s", paragraph)
				t.Logf("Result: %s", result)
				break
			}
		}
	}
}

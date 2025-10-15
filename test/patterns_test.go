package test

import (
	"strings"
	"testing"

	masker "github.com/gocariq/go-sensitive/masker"
	"github.com/stretchr/testify/assert"
)

func TestDefaultPatterns(t *testing.T) {
	patterns := masker.DefaultPatterns()

	assert.Greater(t, len(patterns), 0, "Should have default patterns")

	// Check if common patterns are present
	patternNames := make(map[string]bool)
	for _, pattern := range patterns {
		patternNames[pattern.Name] = true
	}

	assert.True(t, patternNames["credit_card"], "Should have credit_card pattern")
}

func TestCleanNumber(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "cpf with punctuation",
			input:    "123.456.789-00",
			expected: "12345678900",
		},
		{
			name:     "credit card with spaces and dashes",
			input:    "4111 1111-1111 1111",
			expected: "4111111111111111",
		},
		{
			name:     "cnpj with punctuation",
			input:    "12.345.678/0001-90",
			expected: "12345678000190",
		},
		{
			name:     "phone number with punctuation",
			input:    "+55 (11) 99999-9999",
			expected: "+5511999999999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := masker.CleanNumber(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAllDigits(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"all digits", "1234567890", true},
		{"with letters", "123abc456", false},
		{"with spaces", "123 456", false},
		{"with punctuation", "123.456", false},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := masker.IsAllDigits(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPatternMatching(t *testing.T) {
	customPatterns := []masker.Pattern{
		{
			Name:  "credit_card",
			Regex: `\b(?:\d[ -]*?){13,16}\d\b`,
			MaskFunc: func(card string) string {
				cleanCard := masker.CleanNumber(card)
				if len(cleanCard) == 16 && masker.IsAllDigits(cleanCard) {
					return cleanCard[:4] + "********" + cleanCard[12:]
				}
				return card
			},
		},
		{
			Name:  "email",
			Regex: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			MaskFunc: func(email string) string {
				parts := strings.Split(email, "@")
				if len(parts) == 2 {
					username := parts[0]
					if len(username) > 2 {
						return username[:2] + "***@" + parts[1]
					}
					return "***@" + parts[1]
				}
				return email
			},
		},
		{
			Name:  "cpf",
			Regex: `\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`,
			MaskFunc: func(cpf string) string {
				cleanCPF := masker.CleanNumber(cpf)
				if len(cleanCPF) == 11 && masker.IsAllDigits(cleanCPF) {
					return cleanCPF[:3] + "***.***-" + cleanCPF[9:]
				}
				return cpf
			},
		},
		{
			Name:  "cnpj",
			Regex: `\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b`,
			MaskFunc: func(cnpj string) string {
				cleanCNPJ := masker.CleanNumber(cnpj)
				if len(cleanCNPJ) == 14 && masker.IsAllDigits(cleanCNPJ) {
					return cleanCNPJ[:2] + "***.***/****-" + cleanCNPJ[12:]
				}
				return cnpj
			},
		},
		{
			Name:  "phone",
			Regex: `(?:\+?55\s?)?(?:\(?\d{2}\)?[\s-]?)?\d{4,5}[\s-]?\d{4}`,
			MaskFunc: func(phone string) string {
				cleanPhone := masker.CleanNumber(phone)
				if len(cleanPhone) >= 10 && len(cleanPhone) <= 11 && masker.IsAllDigits(cleanPhone) {
					return cleanPhone[:4] + "****" + cleanPhone[8:]
				}
				return phone
			},
		},
	}

	masker := masker.NewWithOpts(masker.WithPatterns(customPatterns))

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "credit card match",
			input:    "4111-1111-1111-1111",
			expected: "4111********1111",
		},
		{
			name:     "cpf match",
			input:    "123.456.789-00",
			expected: "123***.***-00",
		},
		{
			name:     "cnpj match",
			input:    "12.345.678/0001-90",
			expected: "12***.***/****-90",
		},
		{
			name:     "email match",
			input:    "test.user@example.com",
			expected: "te***@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := masker.Mask(tt.input).(string)
			assert.Equal(t, tt.expected, result)
		})
	}
}

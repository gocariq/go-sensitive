package test

import (
	"strings"
	"testing"

	"github.com/gocariq/go-sensitive/masker"
	"github.com/stretchr/testify/assert"
)

type BaseRequest struct {
	ClientID  string `json:"clientId"`
	MessageID string `json:"messageId"`
	BuyerID   string `json:"buyerId"`
}

type AddFundingAccountRequest struct {
	BaseRequest
	AccountNumber  string  `json:"accountNumber"`
	BuyerID        string  `json:"buyerId"`
	DefaultAccount bool    `json:"defaultAccount"`
	CurrencyCode   string  `json:"currencyCode"`
	CreditLimit    float64 `json:"creditLimit"`
	ExpirationDate string  `json:"expirationDate"`
}

func TestMaskData_SimpleString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "credit card with dashes",
			input:    "4111-1111-1111-1111",
			expected: "4111********1111",
		},
		{
			name:     "credit card with spaces",
			input:    "4111 1111 1111 1111",
			expected: "4111********1111",
		},
		{
			name:     "credit card without separators",
			input:    "4111111111111111",
			expected: "4111********1111",
		},
		{
			name:     "regular text unchanged",
			input:    "hello world",
			expected: "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := masker.MaskString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskData_Map(t *testing.T) {
	input := map[string]interface{}{
		"name":        "John Doe",
		"email":       "john.doe@example.com",
		"credit_card": "4111-1111-1111-1111",
		"age":         30,
		"active":      true,
	}

	result := masker.MaskData(input).(map[string]interface{})

	assert.Equal(t, "John Doe", result["name"])
	assert.Equal(t, "john.doe@example.com", result["email"])
	assert.Equal(t, "4111********1111", result["credit_card"])
	assert.Equal(t, 30, result["age"])
	assert.Equal(t, true, result["active"])
}

func TestMaskData_NestedMap(t *testing.T) {
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
	}

	mask := masker.NewWithOpts(masker.WithPatterns(customPatterns))

	input := map[string]interface{}{
		"user": map[string]interface{}{
			"personal_info": map[string]interface{}{
				"name":  "Jane Doe",
				"email": "jane.doe@example.com",
			},
			"payment_methods": []interface{}{
				map[string]interface{}{
					"type":   "credit",
					"number": "5500-0000-0000-0004",
				},
			},
		},
	}

	result := mask.Mask(input).(map[string]interface{})
	user := result["user"].(map[string]interface{})
	personalInfo := user["personal_info"].(map[string]interface{})
	paymentMethods := user["payment_methods"].([]interface{})
	paymentMethod := paymentMethods[0].(map[string]interface{})

	assert.Equal(t, "Jane Doe", personalInfo["name"])
	assert.Equal(t, "ja***@example.com", personalInfo["email"])
	assert.Equal(t, "credit", paymentMethod["type"])
	assert.Equal(t, "5500********0004", paymentMethod["number"])
}

func TestMaskData_Slice(t *testing.T) {
	input := []interface{}{
		"4111-1111-1111-1111",
		"user@example.com",
		"plain text",
		12345,
	}

	result := masker.MaskData(input).([]interface{})

	assert.Equal(t, "4111********1111", result[0])
	assert.Equal(t, "user@example.com", result[1])
	assert.Equal(t, "plain text", result[2])
	assert.Equal(t, 12345, result[3])
}

func TestMaskData_SliceOfMaps(t *testing.T) {
	input := []map[string]interface{}{
		{
			"card":  "4111-1111-1111-1111",
			"email": "test1@example.com",
		},
		{
			"card":  "5500-0000-0000-0004",
			"email": "test2@example.com",
		},
	}

	result := masker.MaskData(input).([]map[string]interface{})

	assert.Equal(t, "4111********1111", result[0]["card"])
	assert.Equal(t, "test1@example.com", result[0]["email"])
	assert.Equal(t, "5500********0004", result[1]["card"])
	assert.Equal(t, "test2@example.com", result[1]["email"])
}

func TestMaskData_RealCase(t *testing.T) {
	input := AddFundingAccountRequest{
		AccountNumber: "4485990014106312",
		BaseRequest: BaseRequest{
			BuyerID:   "5232025",
			ClientID:  "B2BWS_4_9_4477",
			MessageID: "b6fedaf6-02cf-4ce4-bbaa-1af85e822e30",
		},
		ExpirationDate: "12/2026",
	}

	result := masker.MaskDataInterface(input).(map[string]interface{})

	assert.Equal(t, "4485********6312", result["accountNumber"])
	assert.Equal(t, "12/2026", result["expirationDate"])
	assert.Equal(t, "B2BWS_4_9_4477", result["clientId"])
}

func TestMaskData_InterfaceMap(t *testing.T) {
	input := map[interface{}]interface{}{
		"card_number": "4111-1111-1111-1111",
		123:           "should remain unchanged",
		true:          "boolean key",
	}

	result := masker.MaskData(input).(map[interface{}]interface{})

	assert.Equal(t, "4111********1111", result["card_number"])
	assert.Equal(t, "should remain unchanged", result[123])
	assert.Equal(t, "boolean key", result[true])
}

func TestMaskData_PrimitiveTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{"integer", 42, 42},
		{"float", 3.14, 3.14},
		{"boolean true", true, true},
		{"boolean false", false, false},
		{"nil", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := masker.MaskData(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskData_ComplexNestedStructure(t *testing.T) {

	customPatterns := []masker.Pattern{
		{
			Name:  "custom_id",
			Regex: `ID-\d{3}-\d{3}`,
			MaskFunc: func(s string) string {
				return "ID-XXX-XXX"
			},
		},
		{
			Name:  "api_key",
			Regex: `sk-[A-Za-z0-9]{32}`,
			MaskFunc: func(s string) string {
				return "sk-*******************************"
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

	input := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"id":    1,
				"name":  "User One",
				"email": "user1@example.com",
				"documents": map[string]interface{}{
					"cpf":  "111.222.333-44",
					"cnpj": "12.345.678/0001-90",
				},
			},
			map[string]interface{}{
				"id":    2,
				"name":  "User Two",
				"email": "user2@example.com",
				"documents": map[string]interface{}{
					"cpf":  "555.666.777-88",
					"cnpj": "98.765.432/0001-10",
				},
			},
		},
		"metadata": map[string]interface{}{
			"version": "1.0",
			"secure_data": map[string]interface{}{
				"api_key": "should-not-change",
				"token":   "regular-token",
			},
		},
	}

	result := masker.Mask(input).(map[string]interface{})
	users := result["users"].([]interface{})
	user1 := users[0].(map[string]interface{})
	user1Docs := user1["documents"].(map[string]interface{})
	user2 := users[1].(map[string]interface{})
	user2Docs := user2["documents"].(map[string]interface{})
	metadata := result["metadata"].(map[string]interface{})
	secureData := metadata["secure_data"].(map[string]interface{})

	// Test user data
	assert.Equal(t, "User One", user1["name"])
	assert.Equal(t, "us***@example.com", user1["email"])
	assert.Equal(t, "111***.***-44", user1Docs["cpf"])
	assert.Equal(t, "12***.***/****-90", user1Docs["cnpj"])

	assert.Equal(t, "User Two", user2["name"])
	assert.Equal(t, "us***@example.com", user2["email"])
	assert.Equal(t, "555***.***-88", user2Docs["cpf"])
	assert.Equal(t, "98***.***/****-10", user2Docs["cnpj"])

	// Test metadata (should remain unchanged)
	assert.Equal(t, "1.0", metadata["version"])
	assert.Equal(t, "should-not-change", secureData["api_key"])
	assert.Equal(t, "regular-token", secureData["token"])
}

func TestNewMasker_WithCustomPatterns(t *testing.T) {
	customPatterns := []masker.Pattern{
		{
			Name:  "custom_id",
			Regex: `ID-\d{3}-\d{3}`,
			MaskFunc: func(s string) string {
				return "ID-XXX-XXX"
			},
		},
		{
			Name:  "api_key",
			Regex: `sk-[A-Za-z0-9]{32}`,
			MaskFunc: func(s string) string {
				return "sk-*******************************"
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

	mask := masker.NewWithOpts(masker.WithPatterns(customPatterns))

	input := map[string]interface{}{
		"custom_id": "ID-123-456",
		"api_key":   "sk-abc123def456ghi789jkl012mno345pq",
		"email":     "test.user@example.com",
		"cpf":       "011.872.934-09",
		"cnpj":      "98.765.432/0001-10",
		"phone":     "+55 (11) 99999-9999",
	}

	result := mask.Mask(input).(map[string]interface{})

	assert.Equal(t, "ID-XXX-XXX", result["custom_id"])
	assert.Equal(t, "sk-*******************************", result["api_key"])
	assert.Equal(t, "te***@example.com", result["email"])
	assert.Equal(t, "011***.***-09", result["cpf"])
	assert.Equal(t, "98***.***/****-10", result["cnpj"])
	assert.Equal(t, "+55 (11) 99999-9999", result["phone"])

}

func TestMaskData_ConcurrentAccess(t *testing.T) {
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
	}

	mask := masker.NewWithOpts(masker.WithPatterns(customPatterns))

	input := map[string]interface{}{
		"card":  "4111-1111-1111-1111",
		"email": "test@example.com",
	}

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			result := mask.Mask(input).(map[string]interface{})
			assert.Equal(t, "4111********1111", result["card"])
			assert.Equal(t, "te***@example.com", result["email"])
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMaskString_Function(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "credit card",
			input:    "4111-1111-1111-1111",
			expected: "4111********1111",
		},
		{
			name:     "regular text",
			input:    "this is just regular text",
			expected: "this is just regular text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := masker.MaskString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

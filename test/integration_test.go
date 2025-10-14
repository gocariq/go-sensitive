package test

import (
	"testing"

	masker "github.com/gocariq/go-sensitive/masker"
	"github.com/stretchr/testify/assert"
)

func TestIntegration_ComplexBusinessObject(t *testing.T) {

	// Create a complex business object
	transaction := map[string]interface{}{
		"transaction_id": "TXN-12345",
		"user": map[string]interface{}{
			"name":  "John Doe",
			"email": "john.doe@example.com",
			"cpf":   "123.456.789-00",
			"address": map[string]interface{}{
				"street": "123 Main St",
				"city":   "São Paulo",
				"zip":    "01234-567",
			},
		},
		"payment": map[string]interface{}{
			"card_number": "4111-1111-1111-1111",
			"amount":      150.75,
			"currency":    "BRL",
		},
		"metadata": map[string]interface{}{
			"ip_address": "192.168.1.1",
			"user_agent": "Mozilla/5.0...",
		},
	}

	result := masker.MaskData(transaction).(map[string]interface{})
	user := result["user"].(map[string]interface{})
	payment := result["payment"].(map[string]interface{})
	metadata := result["metadata"].(map[string]interface{})

	// Test sensitive data is masked
	assert.Equal(t, "john.doe@example.com", user["email"])
	assert.Equal(t, "123.456.789-00", user["cpf"])
	assert.Equal(t, "4111********1111", payment["card_number"])

	// Test non-sensitive data remains unchanged
	assert.Equal(t, "John Doe", user["name"])
	assert.Equal(t, 150.75, payment["amount"])
	assert.Equal(t, "BRL", payment["currency"])
	assert.Equal(t, "192.168.1.1", metadata["ip_address"])
}

func TestIntegration_MultipleCustomPatterns(t *testing.T) {
	customMasker := masker.New(
		masker.WithCustomPattern("ip_address", `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, func(s string) string {
			return "***.***.***.***"
		}),
		masker.WithCustomPattern("session_id", `session-[A-Za-z0-9]{20}`, func(s string) string {
			return "session-********************"
		}),
	)

	input := map[string]interface{}{
		"ip_address":  "192.168.1.100",
		"session_id":  "session-abc123def456ghi789jk",
		"credit_card": "4111-1111-1111-1111", // Should use default pattern
		"user_agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}

	result := customMasker.Mask(input).(map[string]interface{})

	assert.Equal(t, "***.***.***.***", result["ip_address"])
	assert.Equal(t, "session-********************", result["session_id"])
	assert.Equal(t, "4111-1111-1111-1111", result["credit_card"]) // Default pattern
	assert.Equal(t, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", result["user_agent"])
}

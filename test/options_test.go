package test

import (
	"testing"

	masker "github.com/gocariq/go-sensitive/masker"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	config := masker.DefaultConfig()

	assert.NotNil(t, config.Patterns)
	assert.Greater(t, len(config.Patterns), 0, "Default config should have patterns")
}

func TestWithCustomPattern(t *testing.T) {
	config := masker.DefaultConfig()
	initialLength := len(config.Patterns)

	// Apply custom pattern option
	masker.WithCustomPattern("test", `test-\d+`, func(s string) string {
		return "test-***"
	})(&config)

	assert.Equal(t, initialLength+1, len(config.Patterns), "Should add one custom pattern")

	lastPattern := config.Patterns[len(config.Patterns)-1]
	assert.Equal(t, "test", lastPattern.Name)
	assert.Equal(t, `test-\d+`, lastPattern.Regex)
	assert.NotNil(t, lastPattern.MaskFunc)
}

func TestWithPatterns(t *testing.T) {
	customPatterns := []masker.Pattern{
		{
			Name:  "pattern1",
			Regex: `pattern1`,
			MaskFunc: func(s string) string {
				return "masked1"
			},
		},
		{
			Name:  "pattern2",
			Regex: `pattern2`,
			MaskFunc: func(s string) string {
				return "masked2"
			},
		},
	}

	config := masker.DefaultConfig()
	masker.WithPatterns(customPatterns)(&config)

	assert.Equal(t, customPatterns, config.Patterns, "Should replace all patterns with custom ones")
}

func TestMaskerWithCustomOptions(t *testing.T) {
	customMasker := masker.New(
		masker.WithCustomPattern("zip_code", `\d{5}-\d{3}`, func(s string) string {
			return "*****-***"
		}),
	)

	input := "12345-678"
	result := customMasker.Mask(input).(string)

	assert.Equal(t, "*****-***", result, "Should use custom pattern for zip code")
}

func TestEmptyCustomPattern(t *testing.T) {
	config := masker.DefaultConfig()
	initialLength := len(config.Patterns)

	// Empty regex pattern
	masker.WithCustomPattern("empty", "", func(s string) string {
		return "empty"
	})(&config)

	assert.Equal(t, initialLength+1, len(config.Patterns), "Should add pattern even with empty regex")
}

func TestNilMaskFunc(t *testing.T) {
	config := masker.DefaultConfig()

	// Pattern with nil MaskFunc
	masker.WithCustomPattern("nil_func", `test`, nil)(&config)

	lastPattern := config.Patterns[len(config.Patterns)-1]
	assert.Nil(t, lastPattern.MaskFunc, "MaskFunc should be nil")
}

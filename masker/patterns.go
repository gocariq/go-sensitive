package masker

import (
	"strings"
)

func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			Name:  "credit_card",
			Regex: `\b(?:\d[ -]*?){13,16}\d\b`,
			MaskFunc: func(card string) string {
				cleanCard := CleanNumber(card)
				if len(cleanCard) == 16 && IsAllDigits(cleanCard) {
					return cleanCard[:4] + "********" + cleanCard[12:]
				}
				return card
			},
		},
	}
}

func CleanNumber(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, "/", "")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	return s
}

func IsAllDigits(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

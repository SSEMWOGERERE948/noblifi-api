package placeholders

import "strings"

func Is(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	return normalized == "" ||
		strings.HasPrefix(normalized, "CHANGE_ME") ||
		strings.HasPrefix(normalized, "REPLACE_WITH")
}

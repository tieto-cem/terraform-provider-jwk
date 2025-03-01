package provider

// isValid checks if a given value is in the list of valid values.
func isValid(value string, validValues []string) bool {
	for _, validValue := range validValues {
		if value == validValue {
			return true
		}
	}
	return false
}

package httpapi

// validRequestID accepts 1 to 64 letters, digits or hyphens. Anything else is
// replaced, so client input never reaches response headers or logs unchecked.
func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Package apperr marks errors that are safe to show to the client as validation
// messages. Anything not marked is treated as internal and answered generically.
package apperr

type validationError struct{ msg string }

func (e validationError) Error() string { return e.msg }

// Validation returns an error whose message is safe to send to the client.
func Validation(msg string) error { return validationError{msg: msg} }

// IsValidation reports whether err (or any error it wraps) is a validation error.
func IsValidation(err error) bool {
	for err != nil {
		if _, ok := err.(validationError); ok {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

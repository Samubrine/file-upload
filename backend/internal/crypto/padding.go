package crypto

import (
	"bytes"
	"errors"
)

var ErrInvalidPadding = errors.New("invalid pkcs7 padding")

// PKCS7Pad appends PKCS#7 padding to data for the given blockSize (1 to 255).
// Always adds padding even if len(data) is an exact multiple of blockSize.
func PKCS7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errors.New("invalid block size for pkcs7 padding")
	}
	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	res := make([]byte, len(data)+padLen)
	copy(res, data)
	copy(res[len(data):], padding)
	return res, nil
}

// PKCS7Unpad removes and validates PKCS#7 padding from data for the given blockSize.
// Validates every padding byte.
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errors.New("invalid block size for pkcs7 padding")
	}
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}
	padLen := int(data[len(data)-1])
	if padLen < 1 || padLen > blockSize {
		return nil, ErrInvalidPadding
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, ErrInvalidPadding
		}
	}
	return data[:len(data)-padLen], nil
}


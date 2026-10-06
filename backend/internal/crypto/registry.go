package crypto

import (
	"errors"
	"fmt"
)

// Supported variant IDs
const (
	VariantAES128CBC    = "aes-128-cbc"
	VariantAES128CFB128 = "aes-128-cfb128"
	VariantAES128OFB    = "aes-128-ofb"
	VariantAES128CTR    = "aes-128-ctr"

	VariantAES192CBC    = "aes-192-cbc"
	VariantAES192CFB128 = "aes-192-cfb128"
	VariantAES192OFB    = "aes-192-ofb"
	VariantAES192CTR    = "aes-192-ctr"

	VariantAES256CBC    = "aes-256-cbc"
	VariantAES256CFB128 = "aes-256-cfb128"
	VariantAES256OFB    = "aes-256-ofb"
	VariantAES256CTR    = "aes-256-ctr"

	VariantDESCBC = "des-cbc"
	VariantRC4256 = "rc4-256"
)

const DefaultVariant = VariantAES256CTR

type CipherAlgorithm string

const (
	AlgoAES CipherAlgorithm = "AES"
	AlgoDES CipherAlgorithm = "DES"
	AlgoRC4 CipherAlgorithm = "RC4"
)

type CipherMode string

const (
	ModeCBC    CipherMode = "CBC"
	ModeCFB128 CipherMode = "CFB128"
	ModeOFB    CipherMode = "OFB"
	ModeCTR    CipherMode = "CTR"
	ModeStream CipherMode = "STREAM" // For RC4
)

type VariantSpec struct {
	ID        string
	Algorithm CipherAlgorithm
	KeyBytes  int
	IVBytes   int
	Mode      CipherMode
	BlockSize int
	Padded    bool
}

var Registry = map[string]VariantSpec{
	VariantAES128CBC: {
		ID:        VariantAES128CBC,
		Algorithm: AlgoAES,
		KeyBytes:  16,
		IVBytes:   16,
		Mode:      ModeCBC,
		BlockSize: 16,
		Padded:    true,
	},
	VariantAES128CFB128: {
		ID:        VariantAES128CFB128,
		Algorithm: AlgoAES,
		KeyBytes:  16,
		IVBytes:   16,
		Mode:      ModeCFB128,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES128OFB: {
		ID:        VariantAES128OFB,
		Algorithm: AlgoAES,
		KeyBytes:  16,
		IVBytes:   16,
		Mode:      ModeOFB,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES128CTR: {
		ID:        VariantAES128CTR,
		Algorithm: AlgoAES,
		KeyBytes:  16,
		IVBytes:   16,
		Mode:      ModeCTR,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES192CBC: {
		ID:        VariantAES192CBC,
		Algorithm: AlgoAES,
		KeyBytes:  24,
		IVBytes:   16,
		Mode:      ModeCBC,
		BlockSize: 16,
		Padded:    true,
	},
	VariantAES192CFB128: {
		ID:        VariantAES192CFB128,
		Algorithm: AlgoAES,
		KeyBytes:  24,
		IVBytes:   16,
		Mode:      ModeCFB128,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES192OFB: {
		ID:        VariantAES192OFB,
		Algorithm: AlgoAES,
		KeyBytes:  24,
		IVBytes:   16,
		Mode:      ModeOFB,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES192CTR: {
		ID:        VariantAES192CTR,
		Algorithm: AlgoAES,
		KeyBytes:  24,
		IVBytes:   16,
		Mode:      ModeCTR,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES256CBC: {
		ID:        VariantAES256CBC,
		Algorithm: AlgoAES,
		KeyBytes:  32,
		IVBytes:   16,
		Mode:      ModeCBC,
		BlockSize: 16,
		Padded:    true,
	},
	VariantAES256CFB128: {
		ID:        VariantAES256CFB128,
		Algorithm: AlgoAES,
		KeyBytes:  32,
		IVBytes:   16,
		Mode:      ModeCFB128,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES256OFB: {
		ID:        VariantAES256OFB,
		Algorithm: AlgoAES,
		KeyBytes:  32,
		IVBytes:   16,
		Mode:      ModeOFB,
		BlockSize: 16,
		Padded:    false,
	},
	VariantAES256CTR: {
		ID:        VariantAES256CTR,
		Algorithm: AlgoAES,
		KeyBytes:  32,
		IVBytes:   16,
		Mode:      ModeCTR,
		BlockSize: 16,
		Padded:    false,
	},
	VariantDESCBC: {
		ID:        VariantDESCBC,
		Algorithm: AlgoDES,
		KeyBytes:  8,
		IVBytes:   8,
		Mode:      ModeCBC,
		BlockSize: 8,
		Padded:    true,
	},
	VariantRC4256: {
		ID:        VariantRC4256,
		Algorithm: AlgoRC4,
		KeyBytes:  32,
		IVBytes:   0,
		Mode:      ModeStream,
		BlockSize: 1,
		Padded:    false,
	},
}

// AllVariantIDs returns the 14 supported variant IDs in canonical order
var AllVariantIDs = []string{
	VariantAES128CBC,
	VariantAES128CFB128,
	VariantAES128OFB,
	VariantAES128CTR,
	VariantAES192CBC,
	VariantAES192CFB128,
	VariantAES192OFB,
	VariantAES192CTR,
	VariantAES256CBC,
	VariantAES256CFB128,
	VariantAES256OFB,
	VariantAES256CTR,
	VariantDESCBC,
	VariantRC4256,
}

func GetVariant(id string) (VariantSpec, error) {
	spec, ok := Registry[id]
	if !ok {
		return VariantSpec{}, fmt.Errorf("unknown variant id: %s", id)
	}
	return spec, nil
}

func IsValidVariant(id string) bool {
	_, ok := Registry[id]
	return ok
}

var ErrIntegrityCheckFailed = errors.New("integrity check failed")


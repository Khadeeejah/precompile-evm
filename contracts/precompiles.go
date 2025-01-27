package precompiles

import (
	"errors"

	"github.com/ava-labs/avalanchego/utils/crypto/bls"
)

// BLSSignatureVerify is the precompiled contract for BLS signature verification
type BLSSignatureVerify struct{}

// RequiredGas calculates the gas cost for signature verification
func (c *BLSSignatureVerify) RequiredGas(input []byte) uint64 {
	return 15000 // Estimated base gas cost
}

// Run executes the signature verification
func (c *BLSSignatureVerify) Run(input []byte) ([]byte, error) {
	// Input validation
	const (
		messageHashLen = 32
		publicKeyLen   = 48
		signatureLen   = 96
		totalInputLen  = messageHashLen + publicKeyLen + signatureLen
	)

	if len(input) != totalInputLen {
		return nil, errors.New("invalid input length")
	}

	// Parse input components
	messageHash := input[:messageHashLen]
	publicKeyBytes := input[messageHashLen : messageHashLen+publicKeyLen]
	signatureBytes := input[messageHashLen+publicKeyLen:]

	// Convert bytes to BLS types
	publicKey, err := bls.PublicKeyFromCompressedBytes(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	signature, err := bls.SignatureFromBytes(signatureBytes)
	if err != nil {
		return nil, err
	}

	// Verify signature
	verified := bls.Verify(publicKey, signature, messageHash)

	// Return result as byte (0 for false, 1 for true)
	if verified {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}
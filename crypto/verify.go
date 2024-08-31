// Marcelo Kaihara
// email: marcelo.kaihara at protonmail.com

package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

// VerifySignature verifies the ECDSA signature of the given data using the provided public key.
// The signature is provided as hex-encoded strings for the R and S values.
func VerifySignature(publicKey *ecdsa.PublicKey, data []byte, rHex, sHex string) bool {
	// Decode the hex-encoded R and S values into big.Int types
	rBytes, _ := hex.DecodeString(rHex)
	sBytes, _ := hex.DecodeString(sHex)

	var r, s big.Int
	r.SetBytes(rBytes)
	s.SetBytes(sBytes)

	// Compute the SHA-256 hash of the data
	hash := sha256.Sum256(data)

	// Verify the signature using the public key and the hash
	return ecdsa.Verify(publicKey, hash[:], &r, &s)
}

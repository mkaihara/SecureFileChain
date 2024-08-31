// Marcelo Kaihara
// email: marcelo.kaihara at protonmail.com

package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// SignData takes an ECDSA private key and a byte slice of data, hashes the data using SHA-256,
// and then signs the hash using the private key. It returns the R and S values of the ECDSA
// signature as hex-encoded strings, along with any error that occurred during signing.
func SignData(privateKey *ecdsa.PrivateKey, data []byte) (string, string, error) {
	// Compute the SHA-256 hash of the data
	hash := sha256.Sum256(data)

	// Sign the hash with the provided ECDSA private key
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", "", err
	}

	// Convert the R and S values of the signature to hex strings and return them
	return hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes()), nil
}

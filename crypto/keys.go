// Marcelo Kaihara
// email: marcelo.kaihara at protonmail.com

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// GenerateKeys generates a new ECDSA private and public key pair using the P-256 curve.
// Returns the private key, public key, and an error if any occurred.
func GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// SavePEMKey saves the given ECDSA private key to a file in PEM format.
// The private key is encoded using the x509 standard.
func SavePEMKey(fileName string, key *ecdsa.PrivateKey) error {
	// Create the file to save the private key
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Marshal the private key to DER-encoded form
	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	// Create a PEM block with the DER-encoded private key
	pemKey := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}

	// Encode the PEM block and write it to the file
	err = pem.Encode(outFile, pemKey)
	if err != nil {
		return err
	}
	return nil
}

// LoadPEMKey loads an ECDSA private key from a PEM file.
// The file should contain the private key in x509/DER format.
func LoadPEMKey(fileName string) (*ecdsa.PrivateKey, error) {
	// Read the private key file
	privKeyFile, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block containing the private key
	block, _ := pem.Decode(privKeyFile)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the DER-encoded private key
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// SavePublicPEMKeyToBuffer saves the given ECDSA public key to a provided buffer in PEM format.
// This is useful for storing the public key in memory instead of a file.
func SavePublicPEMKeyToBuffer(buffer io.Writer, pubkey *ecdsa.PublicKey) error {
	// Marshal the public key to DER-encoded form
	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}

	// Create a PEM block with the DER-encoded public key
	pemKey := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubBytes,
	}

	// Encode the PEM block and write it to the buffer
	return pem.Encode(buffer, pemKey)
}

// SavePublicPEMKey saves the given ECDSA public key to a file in PEM format.
// The public key is encoded using the x509 standard.
func SavePublicPEMKey(fileName string, pubkey *ecdsa.PublicKey) error {
	// Create the file to save the public key
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Marshal the public key to DER-encoded form
	pubBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}

	// Create a PEM block with the DER-encoded public key
	pemKey := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubBytes,
	}

	// Encode the PEM block and write it to the file
	err = pem.Encode(outFile, pemKey)
	if err != nil {
		return err
	}
	return nil
}

// LoadPublicPEMKey loads an ECDSA public key from a PEM file.
// The file should contain the public key in x509/DER format.
func LoadPublicPEMKey(fileName string) (*ecdsa.PublicKey, error) {
	// Read the public key file
	pubKeyFile, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block containing the public key
	block, _ := pem.Decode(pubKeyFile)
	if block == nil || block.Type != "EC PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the DER-encoded public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Cast the parsed public key to ECDSA
	return pubKey.(*ecdsa.PublicKey), nil
}

// LoadPublicPEMKeyFromString loads an ECDSA public key from a PEM-encoded string.
// This is useful for loading a public key directly from memory.
func LoadPublicPEMKeyFromString(pubKeyPEM string) (*ecdsa.PublicKey, error) {
	// Decode the PEM block from the string
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "EC PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the DER-encoded public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Cast the parsed public key to ECDSA
	return pubKey.(*ecdsa.PublicKey), nil
}

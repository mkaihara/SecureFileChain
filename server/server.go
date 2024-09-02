// Marcelo Kaihara
// email: marcelo.kaihara at protonmail.com

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"file_uploader/crypto"
	"file_uploader/merkle"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("your_secret_key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Use environment variables for credentials
	username := os.Getenv("SERVER_USERNAME")
	password := os.Getenv("SERVER_PASSWORD")

	// Normally, you'd check the username and password against a database
	if creds.Username != username || creds.Password != password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

// Server struct represents the file server with a directory for storing files and a Merkle tree for integrity verification.
type Server struct {
	filesDir   string
	merkleTree *merkle.MerkleTree
}

// NewServer initializes a new server instance with the given directory for file storage.
func NewServer(filesDir string) *Server {
	return &Server{
		filesDir: filesDir,
	}
}

// saveFile saves the provided data to a file with the given filename in the server's directory.
func (s *Server) saveFile(filename string, data []byte) error {
	filePath := filepath.Join(s.filesDir, filename)
	return os.WriteFile(filePath, data, 0644)
}

// loadFile loads and returns the contents of the file with the given filename from the server's directory.
func (s *Server) loadFile(filename string) ([]byte, error) {
	filePath := filepath.Join(s.filesDir, filename)
	return os.ReadFile(filePath)
}

// DeleteFilesFromDirectory deletes all files in the specified directory.
func DeleteFilesFromDirectory(directory string) error {
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			err = os.Remove(path)
			if err != nil {
				return fmt.Errorf("could not delete file %s: %v", path, err)
			}
			log.Printf("Deleted file: %s", path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("could not delete files in directory %s: %v", directory, err)
	}

	return nil
}

// uploadHandler handles file uploads, verifying signatures, saving the files, and updating the Merkle tree.
func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the uploaded file and related form fields
	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to upload file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	signatureR := r.FormValue("signature_r")
	signatureS := r.FormValue("signature_s")
	publicKeyPEM := r.FormValue("public_key")
	filename := fileHeader.Filename // Get the filename from the FileHeader

	if filename == "" {
		http.Error(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Read the file data into memory
	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Load the public key from the provided PEM string
	publicKey, err := crypto.LoadPublicPEMKeyFromString(publicKeyPEM)
	if err != nil {
		http.Error(w, "Failed to load public key", http.StatusInternalServerError)
		return
	}

	// Verify the signature using the public key
	if !crypto.VerifySignature(publicKey, fileData, signatureR, signatureS) {
		http.Error(w, "Invalid signature", http.StatusForbidden)
		return
	}

	// Save the uploaded file to the server's directory
	err = s.saveFile(filename, fileData)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Save the signature and public key associated with the file
	signatureFile := filename + ".sig"
	signatureData := map[string]string{
		"signature_r": signatureR,
		"signature_s": signatureS,
		"public_key":  publicKeyPEM,
	}
	signatureBytes, _ := json.Marshal(signatureData)
	err = s.saveFile(signatureFile, signatureBytes)
	if err != nil {
		http.Error(w, "Failed to save signature", http.StatusInternalServerError)
		return
	}

	log.Printf("Uploaded, signature verified and saved file: %s", filename)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) updateMerkleTree() error {

	var fileHashes [][]byte
	var filenames []string

	// Load all files in the directory to rebuild the Merkle tree
	err := filepath.Walk(s.filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// Exclude signature files and hidden system files
			if !strings.HasSuffix(info.Name(), ".sig") && info.Name() != ".DS_Store" {
				filenames = append(filenames, info.Name())
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Sort filenames for consistent Merkle tree construction
	sort.Strings(filenames)
	for _, fname := range filenames {
		content, err := s.loadFile(fname)
		if err != nil {
			return err
		}
		fileHashes = append(fileHashes, merkle.HashData(content))
	}

	// Create a new Merkle tree with the updated file hashes
	s.merkleTree = merkle.NewMerkleTree(fileHashes)

	return nil
}

// downloadHandler handles file download requests, including verifying and returning Merkle proof data.
func (s *Server) downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Load the requested file from the server's directory
	fileData, err := s.loadFile(filename)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Load the corresponding signature and public key data
	signatureFile := filename + ".sig"
	signatureBytes, err := s.loadFile(signatureFile)
	if err != nil {
		http.Error(w, "Signature not found", http.StatusInternalServerError)
		return
	}

	var signatureData map[string]string
	err = json.Unmarshal(signatureBytes, &signatureData)
	if err != nil {
		http.Error(w, "Failed to load signature data", http.StatusInternalServerError)
		return
	}

	// Update the Merkle tree after the file is uploaded
	err = s.updateMerkleTree()
	if err != nil {
		http.Error(w, "Failed to update Merkle tree", http.StatusInternalServerError)
		return
	}

	// Find the index of the file in the Merkle tree
	index := -1
	for i, content := range s.merkleTree.Levels[0] {
		if bytes.Equal(content, merkle.HashData(fileData)) {
			index = i
			break
		}
	}

	if index == -1 {
		http.Error(w, "File index not found in Merkle tree", http.StatusInternalServerError)
		return
	}

	// Generate the Merkle proof and directions for the file
	proof, directions := s.merkleTree.GetProof(index)

	// Create the response with file data, signature, and Merkle proof
	response := struct {
		FileData     string   `json:"file_data"`
		SignatureR   string   `json:"signature_r"`
		SignatureS   string   `json:"signature_s"`
		Proof        []string `json:"proof"`
		Directions   []bool   `json:"directions"`
		Root         string   `json:"root"`
		PublicKeyPEM string   `json:"public_key_pem"`
	}{
		FileData:     hex.EncodeToString(fileData),
		SignatureR:   signatureData["signature_r"],
		SignatureS:   signatureData["signature_s"],
		Proof:        make([]string, len(proof)),
		Directions:   directions,
		Root:         hex.EncodeToString(s.merkleTree.Root),
		PublicKeyPEM: signatureData["public_key"],
	}

	for i, p := range proof {
		response.Proof[i] = hex.EncodeToString(p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// merkleRootHandler provides the current Merkle root
func (s *Server) merkleRootHandler(w http.ResponseWriter, r *http.Request) {

	// Update the Merkle tree after the file is uploaded
	err := s.updateMerkleTree()
	if err != nil {
		http.Error(w, "Failed to update Merkle tree", http.StatusInternalServerError)
		return
	}

	if s.merkleTree == nil {
		http.Error(w, "Merkle tree is not available", http.StatusInternalServerError)
		return
	}

	response := struct {
		Root string `json:"root"`
	}{
		Root: hex.EncodeToString(s.merkleTree.Root),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	filesDir := "/app/downloads"
	log.Printf("File storage directory on the server side: %s\n", filesDir)

	// Ensure the directory exists for storing files
	if err := os.MkdirAll(filesDir, os.ModePerm); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	// Clean up any existing files in the directory
	log.Println("Cleaning up existing files in the directory")
	err := DeleteFilesFromDirectory(filesDir)
	if err != nil {
		log.Fatalf("Error deleting files from directory %s: %v", filesDir, err)
	}

	// Initialize the server with the file storage directory
	server := NewServer(filesDir)

	// Register the login handler
	http.HandleFunc("/login", loginHandler) // Add login endpoint

	// Register the upload and download handlers
	http.HandleFunc("/upload", server.uploadHandler)
	http.HandleFunc("/download", server.downloadHandler)

	// Register the Merkle root handler
	http.HandleFunc("/merkle-root", server.merkleRootHandler) // New handler to provide Merkle root

	// Load SSL/TLS certificates for secure communication
	certFile := "/app/cert/cert.pem"
	keyFile := "/app/cert/key.pem"

	// Create a TLS configuration with a minimum version of TLS 1.2
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Set up the HTTP server with TLS configuration
	httpServer := &http.Server{
		Addr:      "server:443", // Change to your server's IP address or domain name
		TLSConfig: tlsConfig,
	}

	log.Printf("Server is running on https://localhost:443\n")
	log.Fatal(httpServer.ListenAndServeTLS(certFile, keyFile))

}

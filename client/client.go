// Marcelo Kaihara
// email: marcelo.kaihara at protonmail.com

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"file_uploader/crypto"
	"file_uploader/merkle"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// GenerateKeyPair generates a new ECDSA key pair (private and public keys).
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, publicKey, err := crypto.GenerateKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate keys: %v", err)
	}
	return privateKey, publicKey, nil
}

// SavePublicKey saves the public key to a file in PEM format.
func SavePublicKey(filename string, publicKey *ecdsa.PublicKey) error {
	err := crypto.SavePublicPEMKey(filename, publicKey)
	if err != nil {
		return fmt.Errorf("could not save public key: %v", err)
	}
	return nil
}

// SignAndUploadFile signs a file and uploads it to the server with the signature and public key.
// It uses a semaphore to control concurrency and a wait group to synchronize the goroutines.
// The function retries the upload if it fails, up to a maximum number of attempts.
func SignAndUploadFile(filename string, client *http.Client, serverURL string, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey, wg *sync.WaitGroup, sem chan struct{}, results chan<- error, maxRetries int) {
	defer wg.Done()

	// Acquire semaphore to limit concurrency
	sem <- struct{}{}
	defer func() {
		// Release semaphore after completion
		<-sem
	}()

	// Open the file for reading
	file, err := os.Open(filename)
	if err != nil {
		results <- fmt.Errorf("could not open file: %v", err)
		return
	}
	defer file.Close()

	// Read the file data into memory
	fileData, err := io.ReadAll(file)
	if err != nil {
		results <- fmt.Errorf("could not read file: %v", err)
		return
	}

	// Sign the file data
	log.Printf("Signing file: %s", filename)
	r, s, err := crypto.SignData(privateKey, fileData)
	if err != nil {
		results <- fmt.Errorf("could not sign file: %v", err)
		return
	}

	for attempts := 0; attempts < maxRetries; attempts++ {
		// Attempt to sign and upload the file
		err = UploadFileWithSignature(filename, client, serverURL, r, s, publicKey)
		if err == nil {
			results <- nil
			return
		}
		log.Printf("Error uploading file %s: %v. Attempt %d/%d", filename, err, attempts+1, maxRetries)
		time.Sleep(2 * time.Second) // wait before retrying
	}

	// If all attempts fail, send the error to the results channel
	results <- fmt.Errorf("failed to upload file %s after %d attempts: %v", filename, maxRetries, err)
}

// UploadFileWithSignature uploads a file to the server along with its digital signature and public key.
func UploadFileWithSignature(filename string, client *http.Client, serverURL string, signatureR string, signatureS string, publicKey *ecdsa.PublicKey) error {

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	// Create a multipart form to upload the file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create a form field for the file
	part, err := writer.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("could not create form file: %v", err)
	}

	// Copy the file content to the form
	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("could not copy file: %v", err)
	}

	// Add the signature and public key fields to the form
	writer.WriteField("signature_r", signatureR)
	writer.WriteField("signature_s", signatureS)

	pubKeyBuffer := &bytes.Buffer{}
	err = crypto.SavePublicPEMKeyToBuffer(pubKeyBuffer, publicKey)
	if err != nil {
		return fmt.Errorf("could not save public key to buffer: %v", err)
	}
	writer.WriteField("public_key", pubKeyBuffer.String())

	// Close the multipart writer to finalize the form
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("could not close writer: %v", err)
	}

	// Create an HTTP POST request to upload the file
	req, err := http.NewRequest("POST", serverURL+"/upload", body)
	if err != nil {
		return fmt.Errorf("could not create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Execute the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not upload file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to upload file: %v", resp.Status)
	}

	log.Printf("File uploaded successfully: %s", filepath.Base(filename))
	return nil
}

// DownloadFileAndVerify downloads a file from the server, verifies its signature and Merkle proof, and saves it locally.
func DownloadFileAndVerify(filename string, client *http.Client, serverURL string, storedRootHash string, fileIndex int, filePath string, publicKey *ecdsa.PublicKey) error {
	baseFilename := filepath.Base(filename)
	log.Printf("Sending HTTP GET request to: %s/download?filename=%s", serverURL, baseFilename)

	// Perform the HTTP GET request to download the file
	resp, err := client.Get(serverURL + "/download?filename=" + baseFilename)
	if err != nil {
		return fmt.Errorf("could not download file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download file: %v", resp.Status)
	}

	log.Println("HTTP GET request successful, status code:", resp.StatusCode)

	// Parse the JSON response
	var result struct {
		FileData     string   `json:"file_data"`
		SignatureR   string   `json:"signature_r"`
		SignatureS   string   `json:"signature_s"`
		Proof        []string `json:"proof"`
		Directions   []bool   `json:"directions"`
		Root         string   `json:"root"`
		PublicKeyPEM string   `json:"public_key_pem"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return fmt.Errorf("could not parse response: %v", err)
	}

	log.Println("Received HTTP response:")
	log.Printf("FileData: %s", result.FileData)
	log.Printf("SignatureR: %s", result.SignatureR)
	log.Printf("SignatureS: %s", result.SignatureS)
	log.Printf("Proof: %v", result.Proof)
	log.Printf("Directions: %v", result.Directions)
	log.Printf("Root: %s", result.Root)
	log.Printf("PublicKeyPEM: %s", result.PublicKeyPEM)

	// Decode the file data from hex
	fileData, err := hex.DecodeString(result.FileData)
	if err != nil {
		return fmt.Errorf("could not decode file data: %v", err)
	}

	// Verify the file's signature
	log.Println("Verifying signature")
	valid := crypto.VerifySignature(publicKey, fileData, result.SignatureR, result.SignatureS)
	if !valid {
		return fmt.Errorf("signature verification failed")
	}
	log.Println("Signature verification succeeded")

	// Save the downloaded file to disk
	filename = filepath.Join(filePath, baseFilename)
	log.Printf("Writing downloaded file to: %s", filename)
	err = os.WriteFile(filename, fileData, 0644)
	if err != nil {
		return fmt.Errorf("could not write file: %v", err)
	}

	// Decode the Merkle proof from hex
	proof := make([][]byte, len(result.Proof))
	for i, p := range result.Proof {
		proof[i], err = hex.DecodeString(p)
		if err != nil {
			return fmt.Errorf("could not decode proof: %v", err)
		}
	}

	// Verify the Merkle proof against the stored root hash
	log.Println("Verifying Merkle proof")
	fileToVerify, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open file %s: %v", filename, err)
	}
	defer fileToVerify.Close()

	leafHash, err := merkle.HashFile(fileToVerify)
	if err != nil {
		return fmt.Errorf("could not hash file %s: %v", filename, err)
	}

	isValid := merkle.VerifyProof(leafHash, proof, result.Directions, storedRootHash)
	if !isValid {
		return fmt.Errorf("file verification failed: proof does not match")
	}
	log.Println("Merkle proof verification succeeded")
	return nil
}

// ReadFileNamesFromDirectory reads all file names from the specified directory and returns them sorted alphabetically.
func ReadFileNamesFromDirectory(directory string) ([]string, error) {
	var filenames []string

	// Walk through the directory and collect file names
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			filenames = append(filenames, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	sort.Strings(filenames)
	return filenames, nil
}

// DeleteFilesFromDirectory deletes all files in the specified directory.
func DeleteFilesFromDirectory(directory string) error {
	// Walk through the directory and delete each file
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

// CheckMerkleRoot retrieves the Merkle root from the server and compares it with the client's Merkle root.
func CheckMerkleRoot(serverURL string, client *http.Client, clientMerkleRoot string) error {
	resp, err := client.Get(serverURL + "/merkle-root")
	if err != nil {
		return fmt.Errorf("could not retrieve Merkle root from server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to retrieve Merkle root: %v", resp.Status)
	}

	var serverMerkleRoot struct {
		Root string `json:"root"`
	}

	err = json.NewDecoder(resp.Body).Decode(&serverMerkleRoot)
	if err != nil {
		return fmt.Errorf("could not decode server Merkle root: %v", err)
	}

	if clientMerkleRoot != serverMerkleRoot.Root {
		return fmt.Errorf("merkle root mismatch: client [%s] vs server [%s]", clientMerkleRoot, serverMerkleRoot.Root)
	}

	log.Println("Merkle root verification succeeded, both roots match.")
	return nil
}

func main() {
	serverURL := "https://server:443"

	// Setup an HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // ONLY for development with self-signed certificates
	}

	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	directory := "/app/data"
	log.Printf("Directory of the files to upload: %s", directory)

	clientDownloadDirectory := "/app/downloads"
	log.Printf("Directory of the file to download from the server: %s", clientDownloadDirectory)

	maxretries := 3 // Maximum number of retries for file uploads
	log.Printf("Maxmum number of retries for file uploads: %d", maxretries)

	fileIndexToVerify := 10 // Index of the file to verify after uploading
	log.Printf("Index of the file to verify after uploading: %d", fileIndexToVerify)

	log.Println("Starting file upload and download process...")

	// Generate keys (private and public)
	log.Println("Generating ECDSA key pair for signing the files...")
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}

	// Delete any existing files in the download directory
	log.Println("Deleting existing files in the download directory on the client side...")
	err = DeleteFilesFromDirectory(clientDownloadDirectory)
	if err != nil {
		log.Fatalf("Error deleting files from directory %s: %v", clientDownloadDirectory, err)
	}

	// Delete any existing files in the download directory
	log.Println("Deleting existing files in the data directory on the client side...")
	err = DeleteFilesFromDirectory(directory)
	if err != nil {
		log.Fatalf("Error deleting files from directory %s: %v", clientDownloadDirectory, err)
	}

	// Create and write files in the data directory
	log.Println("Creating files in the data directory on the client side...")
	numFiles := 20
	log.Printf("Number of files to create: %d", numFiles)
	for i := 0; i < numFiles; i++ {
		filename := filepath.Join(directory, fmt.Sprintf("file_%03d.txt", i+1))
		fileContent := []byte(fmt.Sprintf("%d", i+1))

		err := os.WriteFile(filename, fileContent, 0644)
		if err != nil {
			log.Fatalf("Error creating file %s: %v", filename, err)
		}
	}

	// Read file names from the data directory
	filenames, err := ReadFileNamesFromDirectory(directory)
	if err != nil {
		log.Fatalf("Error reading files from directory: %v", err)
	}

	log.Println("Files in the data directory in alphabetical order:")
	for _, filename := range filenames {
		log.Println(filename)
	}

	// Generate Merkle Tree for the files
	log.Println("Generating Merkle Tree for the files...")
	var fileHashes [][]byte
	for _, filename := range filenames {
		file, err := os.Open(filename)
		if err != nil {
			log.Fatalf("Error opening file %s: %v", filename, err)
		}
		defer file.Close()

		hash, err := merkle.HashFile(file)
		if err != nil {
			log.Fatalf("Error hashing file %s: %v", filename, err)
		}
		fileHashes = append(fileHashes, hash)
	}

	merkleTree := merkle.NewMerkleTree(fileHashes)
	storedRootHash := hex.EncodeToString(merkleTree.Root)
	log.Println("Generated Merkle Root Hash:", storedRootHash)

	// Use a wait group to synchronize the file upload goroutines
	log.Println("----------------------------------------")
	log.Println("Starting file uploads...")
	log.Println("----------------------------------------")
	var wg sync.WaitGroup
	results := make(chan error, len(filenames))

	// Create a semaphore with a buffer of size 2 to limit concurrent uploads
	sem := make(chan struct{}, 2)

	// Upload files concurrently
	for _, filename := range filenames {
		wg.Add(1)
		go SignAndUploadFile(filename, client, serverURL, privateKey, publicKey, &wg, sem, results, maxretries)
	}

	// Wait for all uploads to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Check for any errors during upload
	for err := range results {
		if err != nil {
			log.Fatalf("Error during file upload: %v", err)
		}
	}

	// Compare Merkle roots after uploading all files
	log.Println("----------------------------------------")
	log.Println("Comparing Merkle roots...")
	log.Println("----------------------------------------")
	err = CheckMerkleRoot(serverURL, client, storedRootHash)
	if err != nil {
		log.Fatalf("Merkle root mismatch: %v", err)
		os.Exit(1)
	}

	// After uploading, delete all files in the data directory
	log.Println("----------------------------------------")
	log.Println("Deleting files from the data directory...")
	log.Println("----------------------------------------")
	err = DeleteFilesFromDirectory(directory)
	if err != nil {
		log.Fatalf("Error deleting files from directory %s: %v", directory, err)
	}

	// Download and verify a specific file
	log.Println("----------------------------------------")
	log.Println("Downloading and verifying a single file...")
	log.Printf("File to verify: %s", filenames[fileIndexToVerify])
	log.Println("----------------------------------------")
	if fileIndexToVerify >= 0 && fileIndexToVerify < len(filenames) {
		err = DownloadFileAndVerify(filenames[fileIndexToVerify], client, serverURL, storedRootHash, fileIndexToVerify, clientDownloadDirectory, publicKey)
		if err != nil {
			log.Fatalf("Error downloading or verifying file %s: %v", filenames[fileIndexToVerify], err)
		}
	} else {
		log.Fatalf("Invalid file index to verify: %d", fileIndexToVerify)
	}
}

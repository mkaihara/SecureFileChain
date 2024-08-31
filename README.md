# SecureFileChain
Client-server application for uploading files, downloading a single file, and verifying its integrity to ensure it is not corrupted.

## Overview
This project demonstrates a secure file upload and download service that leverages a Merkle Tree for ensuring data consistency and ECDSA (Elliptic Curve Digital Signature Algorithm) for file integrity verification. The system consists of a server and a client, both implemented in Go, which interact with each other over HTTPS. The project is containerized using Docker, making it easy to set up and run.

## Features
* Merkle Tree for Integrity Verification: The server constructs a Merkle Tree from the uploaded files, allowing clients to verify the integrity of a specific file against the tree's root hash.
* File Upload with Signature Verification: The client signs each file using ECDSA before uploading it to the server. The server verifies the signature to ensure the file's integrity.
* Secure Communication: The communication between the client and server is secured using TLS.
* Concurrent Uploads: The client supports concurrent file uploads with retry logic in case of failures.
* Dockerized Environment: The entire system can be easily set up and run using Docker and Docker Compose.

## Project Structure
```
.
├── client
│   ├── client.go         # Client-side application code
│   ├── Dockerfile        # Dockerfile for building the client image  
├── data                  # Directory containing the files to transfer to the server
├── download_client       # Directory where the single file will be downloaded from the server
├── server
│   ├── server.go         # Server-side application code
│   ├── Dockerfile        # Dockerfile for building the server image
│   └── cert
│       ├── cert.pem      # SSL certificate for secure communication
│       └── key.pem       # Private key for SSL certificate
├── download_server       # Directory where the files will be uploaded
├── crypto
│   ├── keys.go           # ECDSA key generation and handling
│   ├── sign.go           # ECDSA signing implementation
│   └── verify.go         # ECDSA signature verification
├── merkle
│   └── merkle_tree.go    # Merkle Tree implementation
├── docker-compose.yml    # Docker Compose configuration
└── go.mod                # Go module definition
```

## Setup Instructions
### Prerequisites

* Docker and Docker Compose installed on your system.

### Building and Running the Project

1. Clone the Repository:
```bash
git clone https://github.com/mkaihara/SecureFileChain.git
cd SecureFileChain
```   
2. Start the Services:
```bash
docker-compose up --build
```
* The client will automatically generate, sign, upload files to the server, and then verify the files using the Merkle tree.

## Customization
* File Directories:

  * The client uploads files from the /app/data directory inside the client container.
  * The client download single files to the /app/downloads directory inside the client container.
  * The server saves uploaded files in the /app/downloads directory inside the server container.
  * These directories are mounted as volumes in the Docker containers and can be customized by modifying the docker-compose.yml file.

* TLS Certificates:

  * The server uses self-signed certificates located in the server/cert directory.
  * If you have your own certificates, replace the cert.pem and key.pem files in the server/cert directory.

## Technical Details
### Server

The server is responsible for handling file uploads, verifying signatures, and maintaining a Merkle tree to ensure the integrity of the stored files. It exposes the following endpoints:

* /upload: Handles file uploads, verifies the ECDSA signature, and saves the file if the signature is valid.
* /download: Provides a file download along with the associated Merkle proof, allowing clients to verify the file's integrity.
* /merkle-root: Returns the current Merkle root of the files stored on the server.

### Client

The client is responsible for signing files, uploading them to the server, and verifying the files after download using the Merkle proof. It also generates a Merkle tree for the files before uploading to ensure consistency with the server's Merkle root.

### Merkle Tree
A Merkle tree is a binary tree of hashes that provides an efficient way to verify the integrity of a large set of data. In this project, it is used to ensure that the files stored on the server have not been tampered with.

## Security Considerations

* Merkle Tree: The Merkle tree structure allows for efficient and secure verification of file integrity.

* ECDSA Signatures: Every file is signed using ECDSA, providing cryptographic assurance of the file's origin and integrity.

* TLS/SSL: The server and client communicate over HTTPS to ensure that the data in transit is encrypted.

### Contact

Marcelo Kaihara - marcelo.kaihara@protonmail.com

Feel free to reach out if you have any questions or suggestions!



  

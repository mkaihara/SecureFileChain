# SecureFileChain
Client-server application for uploading files, downloading a single file, and verifying its integrity to ensure it is not corrupted.

## Overview
This project demonstrates a secure file upload and download service that leverages a Merkle Tree for ensuring data consistency and ECDSA (Elliptic Curve Digital Signature Algorithm) for file integrity verification. The system consists of a server and a client, both implemented in Go, which interact with each other over HTTPS. The system includes user authentication using JWT (JSON Web Tokens), ensuring that only authorized users can upload or download files. The project is containerized using Docker, making it easy to set up and run.

## Features
* Merkle Tree for Integrity Verification: The server constructs a Merkle Tree from the uploaded files, allowing clients to verify the integrity of a specific file against the tree's root hash.
* File Upload with Signature Verification: The client signs each file using ECDSA before uploading it to the server. The server verifies the signature to ensure the file's integrity.
* User Authentication with JWT: Users must log in to the server to obtain a JWT token, which is required for all subsequent file upload and download operations.
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

## Authentication
* Login Process: The client logs in to the server using a username and password to obtain a JWT token. This token is required for all subsequent requests to upload or download files.
* Token Handling: The client automatically includes the JWT token in the Authorization header of each request, ensuring that only authenticated users can interact with the server.

## Customization
To customize various aspects of the file uploader application, you can adjust the following environment variables in the `docker-compose.yml` file:

1. File Index to Download:

    * The file index to download is controlled by the `INDEX_TO_DOWNLOAD` environment variable in the client service configuration. This index should be a number between `0` and `NUM_FILES_TO_CREATE - 1`.
    * Example:
    ```yaml
         - INDEX_TO_DOWNLOAD=10
    ```
    * This will configure the client to download the file with index `10` after the upload process.
  
2. Max Number of Files to Create:

   * The maximum number of files to create is set by the `NUM_FILES_TO_CREATE` environment variable. This determines how many files will be created in the data folder by the client before they are uploaded to the server.
   * Example:
   ```yaml
         - NUM_FILES_TO_CREATE=20
   ```
   * This will create 20 files in the client’s data directory.
  
3. Max Retries to Upload a File:

   * The maximum number of retries to upload a file is controlled by the `MAX_RETRIES_UPLOAD` environment variable. This variable sets the number of times the client will attempt to upload a file to the server if the initial attempt fails.
   * Example:
   ```yaml
         - MAX_RETRIES_UPLOAD=3
   ```
   * This setting allows the client to retry uploading a file up to three times if there are any issues.

4. Username and Password Configuration:

   * The username and password used for authenticating with the server are specified by the `CLIENT_USERNAME`, `CLIENT_PASSWORD`, `SERVER_USERNAME`, and `SERVER_PASSWORD` environment variables in the docker-compose.yml file.
   * Example:
   ```yaml
         - CLIENT_USERNAME=username
         - CLIENT_PASSWORD=secret_password
   ```
   * These credentials are used for logging in to the server, and they must match the corresponding server environment variables.

* File Directories:

  * The client uploads files from the /app/data directory inside the client container, which is mapped to the /data volume.
  * The client downloads individual files to the /app/downloads directory inside the client container, which is mapped to the /download_client volume.
  * The server saves uploaded files in the /app/downloads directory inside the server container, which is mapped to the /download_server volume.
  * These directories are mounted as volumes in the Docker containers and can be customized by modifying the docker-compose.yml file.

* TLS Certificates:

  * The server uses self-signed certificates located in the server/cert directory.
  * If you have your own certificates, replace the cert.pem and key.pem files in the server/cert directory.
    
## Technical Details
### Server

The server is responsible for handling file uploads, verifying signatures, managing user authentication with JWT, and maintaining a Merkle tree to ensure the integrity of the stored files. It exposes the following endpoints:

* /login: Authenticates the user and returns a JWT token.
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

* JWT Authentication: Users must authenticate with a username and password to receive a JWT token. This token is required for all subsequent interactions with the server.


### Contact

Marcelo Kaihara - marcelo.kaihara@protonmail.com

Feel free to reach out if you have any questions or suggestions!



  

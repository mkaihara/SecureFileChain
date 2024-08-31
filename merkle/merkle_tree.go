package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// HashData computes the SHA-256 hash of the given data.
// Returns the hash as a byte slice.
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashFile computes the SHA-256 hash of the contents of a given file.
// It reads the file's content and returns the hash or an error if any occurs.
func HashFile(file *os.File) ([]byte, error) {
	hasher := sha256.New()
	_, err := io.Copy(hasher, file)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// hashPair concatenates two byte slices and returns their combined SHA-256 hash.
// This function is used to hash pairs of nodes in the Merkle tree.
func hashPair(left, right []byte) []byte {
	return HashData(append(left, right...))
}

// MerkleTree represents the structure of a Merkle tree.
// It contains the root hash and all levels of the tree.
type MerkleTree struct {
	Root   []byte     // Root hash of the tree
	Levels [][][]byte // All levels of the tree from leaves to root
}

// NewMerkleTree creates a new Merkle tree from the given file hashes and returns it.
// It initializes the tree, generates all levels, and computes the root hash.
func NewMerkleTree(fileHashes [][]byte) *MerkleTree {
	// Generate all levels of the Merkle tree
	levels := generateTreeLevels(fileHashes)

	// The root is the last remaining hash after building the tree
	root := levels[len(levels)-1][0]

	return &MerkleTree{
		Root:   root,
		Levels: levels,
	}
}

// generateTreeLevels builds the Merkle tree by computing all levels from the leaves up to the root.
// Returns a slice of byte slices representing the levels of the tree.
func generateTreeLevels(leaves [][]byte) [][][]byte {
	if len(leaves) == 0 {
		return nil
	}

	levels := [][][]byte{leaves} // Start with the leaves as the first level
	for {
		currentLevel := levels[len(levels)-1]
		if len(currentLevel) == 1 {
			break // Stop when only one node (the root) remains
		}

		// Generate the next level by hashing pairs of nodes
		nextLevel := generateNextLevel(currentLevel)
		levels = append(levels, nextLevel)
	}
	return levels
}

// generateNextLevel creates the next level in the Merkle tree by hashing pairs of nodes from the current level.
// If the current level has an odd number of nodes, the last node is paired with itself.
func generateNextLevel(currentLevel [][]byte) [][]byte {
	nextLevel := make([][]byte, (len(currentLevel)+1)/2) // Prepare space for the next level
	for i := 0; i < len(currentLevel); i += 2 {
		if i+1 < len(currentLevel) {
			// Pair nodes together and hash them
			nextLevel[i/2] = hashPair(currentLevel[i], currentLevel[i+1])
		} else {
			// Handle the case of an odd number of nodes by pairing the last node with itself
			nextLevel[i/2] = hashPair(currentLevel[i], currentLevel[i])
		}
	}
	return nextLevel
}

// GetProof generates a Merkle proof for a given leaf index in the tree.
// The proof is a sequence of sibling hashes needed to reconstruct the root from the leaf.
// Directions indicate whether the sibling is a left or right node relative to the current node.
func (mt *MerkleTree) GetProof(index int) ([][]byte, []bool) {
	proof := [][]byte{}
	directions := []bool{}
	nodeIndex := index

	// Traverse up the tree to collect sibling hashes and their directions
	for level := 0; level < len(mt.Levels)-1; level++ {
		levelNodes := mt.Levels[level]

		if nodeIndex%2 == 0 { // Even index means the sibling is on the right
			if nodeIndex+1 < len(levelNodes) {
				proof = append(proof, levelNodes[nodeIndex+1])
				directions = append(directions, false) // Sibling is on the right
			} else if nodeIndex == len(levelNodes)-1 {
				// Last node at the current level; duplicate its hash
				proof = append(proof, levelNodes[nodeIndex])
				directions = append(directions, false) // Sibling is on the right
			}
		} else { // Odd index means the sibling is on the left
			proof = append(proof, levelNodes[nodeIndex-1])
			directions = append(directions, true) // Sibling is on the left
		}
		nodeIndex /= 2
	}
	return proof, directions
}

// VerifyProof checks the validity of a Merkle proof by reconstructing the root hash from the leaf hash.
// It compares the reconstructed root with the provided root hash.
func VerifyProof(leafHash []byte, proof [][]byte, directions []bool, rootHash string) bool {
	currentHash := leafHash
	for i, siblingHash := range proof {
		if directions[i] {
			// True indicates the sibling is on the left, so we hash (siblingHash || currentHash)
			currentHash = hashPair(siblingHash, currentHash)
		} else {
			// False indicates the sibling is on the right, so we hash (currentHash || siblingHash)
			currentHash = hashPair(currentHash, siblingHash)
		}
	}
	// Return whether the computed root matches the provided root hash
	return hex.EncodeToString(currentHash) == rootHash
}

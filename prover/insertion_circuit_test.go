package prover

import (
	"crypto/rand"
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/stretchr/testify/require"

	poseidon "worldcoin/gnark-mbu/poseidon_native"
)

var ctx, _ = gokzg4844.NewContext4096Secure()

const (
	numGoRoutines      = 0
	existingUsersCount = 16384
	incomingUsersCount = polynomialDegree
)

func TestInsertionCircuit(t *testing.T) {
	incomingIds := generateRandomIdentities(incomingUsersCount)
	smallTree := poseidon.NewTree(treeDepth(incomingUsersCount))
	idComms := make([]frontend.Variable, incomingUsersCount)
	for i, id := range incomingIds {
		idComms[i] = id
		_ = smallTree.Update(i, id)
	}
	incomingIdsTreeRoot := smallTree.Root()
	incomingIdsTreeRoot = *bytesToBn254BigInt(incomingIdsTreeRoot.Bytes())

	idsBytes := bigIntsToBytes(incomingIds)
	blob := bytesToBlob(idsBytes)
	commitment, err := ctx.BlobToKZGCommitment(blob, numGoRoutines)
	require.NoError(t, err)
	commitment4844 := bytesToBn254BigInt(commitment[:])

	var rootAndCommitment []byte
	rootAndCommitment = append(rootAndCommitment, incomingIdsTreeRoot.Bytes()...)
	rootAndCommitment = append(rootAndCommitment, commitment[:]...)
	challenge := keccak256.Hash(rootAndCommitment)
	challenge = bytesToBn254BigInt(challenge).Bytes()
	if len(challenge) < 32 {
		// Make sure challenge is 32-byte-long so ComputeKZGProof is happy
		paddedChallenge := make([]byte, 32)
		copy(paddedChallenge[32-len(challenge):], challenge)
		challenge = paddedChallenge
	}
	proof, evaluation, err := ctx.ComputeKZGProof(blob, [32]byte(challenge), numGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyKZGProof(commitment, [32]byte(challenge), evaluation, proof)
	require.NoError(t, err)
	expectedEvaluation := bytesToBn254BigInt(evaluation[:])

	existingIdsTreeDepth := treeDepth(existingUsersCount)
	existingIds := generateRandomIdentities(existingUsersCount)
	bigTree := poseidon.NewTree(existingIdsTreeDepth)
	preRoot := bigTree.Root()
	merkleProofs := make([][]frontend.Variable, existingUsersCount)
	for i, id := range existingIds {
		update := bigTree.Update(i, id)
		merkleProofs[i] = make([]frontend.Variable, len(update))
		for j, v := range update {
			merkleProofs[i][j] = v
		}
	}
	postRoot := bigTree.Root()

	circuit := InsertionMbuCircuit{
		IdComms:      make([]frontend.Variable, incomingUsersCount),
		MerkleProofs: make([][]frontend.Variable, existingUsersCount),
		Depth:        existingIdsTreeDepth,
	}
	for i, mp := range merkleProofs {
		circuit.MerkleProofs[i] = make([]frontend.Variable, len(mp))
	}

	assignment := InsertionMbuCircuit{
		InputHash:          incomingIdsTreeRoot,
		ExpectedEvaluation: expectedEvaluation,
		Commitment4844:     commitment4844,
		StartIndex:         existingUsersCount,
		PreRoot:            preRoot,
		PostRoot:           postRoot,
		IdComms:            idComms,
		MerkleProofs:       merkleProofs,
		Depth:              existingIdsTreeDepth,
	}

	assert := test.NewAssert(t)
	assert.CheckCircuit(
		&circuit, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254),
		test.WithValidAssignment(&assignment),
	)
}

// generateRandomIdentities generates a slice of random big integers reduced modulo BN254 FR,
// but not smaller than modulo/4, of the given count.
func generateRandomIdentities(count int) []big.Int {
	ids := make([]big.Int, count)
	modulus := bn254fr.Modulus()
	minVal := new(big.Int).Div(modulus, big.NewInt(4)) // modulus / 4

	for i := range ids {
		n, _ := rand.Int(rand.Reader, modulus)
		if n.Cmp(minVal) < 0 {
			n = minVal
		}
		ids[i] = *n
	}

	return ids
}

// bigIntsToBytes converts a slice of big.Int into a single slice of bytes.
// Each big.Int is converted to its byte representation and padded to 32 bytes with leading zeros, if necessary.
func bigIntsToBytes(bigInts []big.Int) []byte {
	var b []byte
	for _, bigInt := range bigInts {
		value := bigInt.Bytes()
		// Pad to 32 bytes with zeros
		if len(value) < 32 {
			pad := make([]byte, 32-len(value))
			value = append(pad, value...)
		}
		b = append(b, value...)
	}
	return b
}

// bytesToBlob converts a slice of bytes into a KZG 4844 Blob
func bytesToBlob(idsBytes []byte) *gokzg4844.Blob {
	var blob gokzg4844.Blob
	copy(blob[:], idsBytes)
	return &blob
}

// bytesToBn254BigInt converts a slice of bytes to a *big.Int and reduces it by BN254 modulus
func bytesToBn254BigInt(b []byte) *big.Int {
	n := new(big.Int).SetBytes(b)
	modulus := bn254fr.Modulus()
	return n.Mod(n, modulus)
}

// treeDepth calculates the depth of a binary tree containing the given number of leaves
func treeDepth(leavesCount int) (height int) {
	if leavesCount <= 0 {
		return 0
	}
	height = int(math.Ceil(math.Log2(float64(leavesCount))))
	return
}

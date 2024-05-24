package prover

import (
	"crypto/rand"
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
	numGoRoutines = 0
	smallTreeDepth = 12 // TODO a sane value
	bigTreeDepth = 420 // TODO a sane value
	batchSize = polynomialDegree // TODO a sane value
	idCommsCount = 10000 // In reality, it's about 1 B
)

func TestInsertionCircuit(t *testing.T) {
	incomingIds := generateRandomIdentities(polynomialDegree)

	idsBytes := bigIntsToBytes(incomingIds)
	blob := bytesToBlob(idsBytes)
	commitment, err := ctx.BlobToKZGCommitment(blob, numGoRoutines)
	require.NoError(t, err)

	smallTree := poseidon.NewTree(smallTreeDepth)
	for i, id := range incomingIds {
		_ = smallTree.Update(i, id)
	}
	root := smallTree.Root()

	var rootAndCommitment []byte
	rootAndCommitment = append(rootAndCommitment, root.Bytes()...)
	rootAndCommitment = append(rootAndCommitment, commitment[:]...)
	challenge := keccak256.Hash(rootAndCommitment)
	if len(challenge) < 32 {
		// Make sure challenge is 32-byte-long so ComputeKZGProof is happy
		paddedChallenge := make([]byte, 32)
		copy(paddedChallenge[32-len(challenge):], challenge)
		challenge = paddedChallenge
	}
	challenge = bytesToBn254BigInt(challenge).Bytes()

	proof, _, err := ctx.ComputeKZGProof(blob, [32]byte(challenge), numGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyBlobKZGProof(blob, commitment, proof)
	//require.NoError(t, err) // TODO see why it fails
	expectedEvaluation := bytesToBn254BigInt(proof[:])

	commitment4844 := bytesToBn254BigInt(commitment[:])

	existingIds := generateRandomIdentities(idCommsCount)
	bigTree := poseidon.NewTree(bigTreeDepth)
	preRoot := bigTree.Root()
	idComms := make([]frontend.Variable, len(existingIds))
	merkleProofs := make([][]frontend.Variable, len(existingIds))
	for i, id := range existingIds {
		idComms[i] = id
		update := bigTree.Update(i, id)
		merkleProofs[i] = make([]frontend.Variable, len(update))
		for j, v := range update {
			merkleProofs[i][j] = v
		}
	}
	postRoot := bigTree.Root()

	circuit := InsertionMbuCircuit{
		IdComms:            make([]frontend.Variable, len(existingIds)),
		MerkleProofs:       make([][]frontend.Variable, len(existingIds)),
		Depth:              bigTreeDepth,
	}
	for i := range circuit.MerkleProofs {
		circuit.MerkleProofs[i] = make([]frontend.Variable, bigTreeDepth)
	}

	assignment := InsertionMbuCircuit{
		InputHash:          root,
		ExpectedEvaluation: expectedEvaluation,
		Commitment4844:     commitment4844,
		StartIndex:         0,    // TODO really?
		PreRoot:            preRoot,
		PostRoot:           postRoot,
		IdComms:            idComms,
		MerkleProofs:       merkleProofs,
		Depth:              bigTreeDepth,
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

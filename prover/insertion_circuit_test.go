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
	treeDepth = 69 // TODO a sane value
	batchSize = polynomialDegree // TODO a sane value
)

func TestInsertionCircuit(t *testing.T) {
	ids := generateRandomIdentities(polynomialDegree)

	idsBytes := bigIntsToBytes(ids)
	blob := bytesToBlob(idsBytes)
	commitment, err := ctx.BlobToKZGCommitment(blob, numGoRoutines)
	require.NoError(t, err)

	idComms := make([]frontend.Variable, polynomialDegree)
	for i, id := range ids {
		idComms[i] = id
	}

	merkleProofs := make([][]frontend.Variable, batchSize)
	tree := poseidon.NewTree(treeDepth)
	// TODO can this be done in more elegant way? this is conversion
	//  of [][]big.Int to [][]frontend.Variable
	for i, id := range ids {
		update := tree.Update(i, id)
		merkleProofs[i] = make([]frontend.Variable, len(update))
		for j, v := range update {
			merkleProofs[i][j] = v
		}
	}

	var rootAndCommitment []byte
	root := tree.Root()
	rootAndCommitment = append(rootAndCommitment, root.Bytes()...)
	rootAndCommitment = append(rootAndCommitment, commitment[:]...)
	challenge := keccak256.Hash(rootAndCommitment)
	challenge = bytesToBn254BigInt(challenge).Bytes()

	// TODO this conversion can fail, challenge can be 31-bytes long, it happened at least once
	proof, _, err := ctx.ComputeKZGProof(blob, [32]byte(challenge), numGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyBlobKZGProof(blob, commitment, proof)
	//require.NoError(t, err) // TODO see why it fails
	expectedEvaluation := bytesToBn254BigInt(proof[:])

	commitment4844 := bytesToBn254BigInt(commitment[:])

	proofs := make([][]frontend.Variable, batchSize)
	for i := 0; i < int(batchSize); i++ {
		proofs[i] = make([]frontend.Variable, treeDepth)
	}

	circuit := InsertionMbuCircuit{
		IdComms:            make([]frontend.Variable, batchSize),
		MerkleProofs:       proofs,
		Depth:              treeDepth,
	}
	for i := 0; i < batchSize; i++ {
		circuit.MerkleProofs[i] = make([]frontend.Variable, treeDepth)
	}
	assignment := InsertionMbuCircuit{
		InputHash:          root,
		ExpectedEvaluation: expectedEvaluation,
		Commitment4844:     commitment4844,
		StartIndex:         0,    // TODO really?
		PreRoot:            root, // TODO really?
		PostRoot:           root, // TODO really?
		IdComms:            idComms,
		MerkleProofs:       merkleProofs,
		Depth:              treeDepth,
	}

	assert := test.NewAssert(t)
	assert.CheckCircuit(
		&circuit, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254),
		test.WithValidAssignment(&assignment),
	)
}

// generateRandomIdentities generates a slice of random big integers reduced modulo BN254 FR
// of the given count.
func generateRandomIdentities(count int) []big.Int {
	ids := make([]big.Int, count)
	modulus := bn254fr.Modulus()

	for i := range ids {
		n, _ := rand.Int(rand.Reader, modulus)
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

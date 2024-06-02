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

	blob := identitiesToBlob(incomingIds)
	commitment, err := ctx.BlobToKZGCommitment(blob, numGoRoutines)
	require.NoError(t, err)
	commitment4844 := *bytesToBn254BigInt(commitment[:])

	challenge := bigIntsToChallenge([]big.Int{incomingIdsTreeRoot, commitment4844})
	proof, evaluation, err := ctx.ComputeKZGProof(blob, challenge, numGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyKZGProof(commitment, challenge, evaluation, proof)
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

// identitiesToBlob converts a slice of big.Int into a KZG 4844 Blob.
func identitiesToBlob(ids []big.Int) *gokzg4844.Blob {
	if len(ids) > gokzg4844.ScalarsPerBlob {
		panic("too many identities for a blob")
	}

	var b []byte
	for _, id := range ids {
		b = append(b, id.Bytes()...)
	}

	var blob gokzg4844.Blob
	copy(blob[:], b)
	return &blob
}

// bytesToBn254BigInt converts a slice of bytes to a *big.Int and reduces it by BN254 modulus
func bytesToBn254BigInt(b []byte) *big.Int {
	n := new(big.Int).SetBytes(b)
	modulus := bn254fr.Modulus()
	return n.Mod(n, modulus)
}

// bigIntsToChallenge converts input bit.Ints to a challenge for a proof of knowledge of a polynomial.
// The challenge is defined as a gokzg4844.Scalar of a keccak256 hash of all input big.Ints reduced
// by BN254 modulus.
func bigIntsToChallenge(input []big.Int) (challenge gokzg4844.Scalar) {
	var inputBytes []byte
	for _, i := range input {
		inputBytes = append(inputBytes, i.Bytes()...)
	}

	// Reduce keccak because gokzg4844 API expects that
	hashBytes := bytesToBn254BigInt(keccak256.Hash(inputBytes)).Bytes()

	copy(challenge[:], hashBytes)
	return challenge
}


// treeDepth calculates the depth of a binary tree containing the given number of leaves
func treeDepth(leavesCount int) (height int) {
	if leavesCount <= 0 {
		return 0
	}
	height = int(math.Ceil(math.Log2(float64(leavesCount))))
	return
}

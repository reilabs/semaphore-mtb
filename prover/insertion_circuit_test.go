package prover

import (
	"encoding/hex"
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/stretchr/testify/require"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	poseidon "worldcoin/gnark-mbu/poseidon_native"
)

const (
	numGoRoutines      = 0
	existingUsersCount = 0
	batchSize          = 3
	depth              = 16
)

func TestInsertionCircuit(t *testing.T) {
	incomingIds := generateRandomIdentities(batchSize)
	smallTree := poseidon.NewTree(treeDepth(polynomialDegree))
	idComms := make([]frontend.Variable, batchSize)
	for i, id := range incomingIds {
		idComms[i] = id
		smallTree.Update(i, id)
	}
	incomingIdsTreeRoot := smallTree.Root()
	incomingIdsTreeRoot = *BytesToBn254BigInt(incomingIdsTreeRoot.Bytes())

	ctx, err := gokzg4844.NewContext4096Secure()
	require.NoError(t, err)
	blob := identitiesToBlob(incomingIds)
	commitment, err := ctx.BlobToKZGCommitment(blob, numGoRoutines)
	require.NoError(t, err)
	versionedKzgHash := KzgToVersionedHash(commitment)
	versionedKzgHashReduced := *BytesToBn254BigInt(versionedKzgHash[:])

	challenge := bigIntsToChallenge([]big.Int{incomingIdsTreeRoot, versionedKzgHashReduced})
	proof, evaluation, err := ctx.ComputeKZGProof(blob, challenge, numGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyKZGProof(commitment, challenge, evaluation, proof)
	require.NoError(t, err)

	existingIds := generateRandomIdentities(existingUsersCount)
	bigTree := poseidon.NewTree(depth)
	for i, id := range existingIds {
		bigTree.Update(i, id)
	}
	preRoot := bigTree.Root()
	merkleProofs := make([][]frontend.Variable, batchSize)
	for i, id := range incomingIds {
		mp := bigTree.Update(i+existingUsersCount, id)
		merkleProofs[i] = make([]frontend.Variable, len(mp))
		for j, v := range mp {
			merkleProofs[i][j] = v
		}
	}
	postRoot := bigTree.Root()

	circuit := InsertionMbuCircuit{
		IdComms:      make([]frontend.Variable, batchSize),
		MerkleProofs: make([][]frontend.Variable, batchSize),
		BatchSize:    batchSize,
		Depth:        depth,
	}
	for i := range merkleProofs {
		circuit.MerkleProofs[i] = make([]frontend.Variable, depth)
	}

	assignment := InsertionMbuCircuit{
		InputHash:          incomingIdsTreeRoot,
		ExpectedEvaluation: *BytesToBn254BigInt(evaluation[:]),
		Commitment4844:     versionedKzgHashReduced,
		StartIndex:         existingUsersCount,
		PreRoot:            preRoot,
		PostRoot:           postRoot,
		IdComms:            idComms,
		MerkleProofs:       merkleProofs,
		BatchSize:          batchSize,
		Depth:              depth,
	}

	log.Printf("ExpectedEvaluation: 0x%s\n", hex.EncodeToString(evaluation[:]))
	log.Printf("kzgCommitmentReduced: 0x%s\n", versionedKzgHashReduced.Text(16))
	log.Printf("kzgChallenge: 0x%s\n", hex.EncodeToString(challenge[:]))
	kzgProofParts := []string{
		"0x" + hex.EncodeToString(proof[:16]),
		"0x" + hex.EncodeToString(proof[16:32]),
		"0x" + hex.EncodeToString(proof[32:48]),
	}
	log.Printf("kzgProof = [%s, %s, %s]\n", kzgProofParts[0], kzgProofParts[1], kzgProofParts[2])

	kzgCommitmentParts := []string{
		"0x" + hex.EncodeToString(commitment[:16]),
		"0x" + hex.EncodeToString(commitment[16:32]),
		"0x" + hex.EncodeToString(commitment[32:48]),
	}
	log.Printf("kzgCommitment = [%s, %s, %s]\n", kzgCommitmentParts[0], kzgCommitmentParts[1], kzgCommitmentParts[2])

	assert := test.NewAssert(t)
	assert.CheckCircuit(
		&circuit, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254),
		test.WithValidAssignment(&assignment),
	)
}

// generateRandomIdentities generates a slice of random big integers reduced modulo BN254 FR.
func generateRandomIdentities(count int) []big.Int {
	ids := make([]big.Int, count)
	for i := range ids {
		// n, _ := rand.Int(rand.Reader, bn254fr.Modulus())
		ids[i] = *big.NewInt(int64(i))
	}
	return ids
}

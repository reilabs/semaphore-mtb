package prover

import (
	"crypto/rand"
	"math/big"
	"testing"

	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/stretchr/testify/require"
)

var ctx, _ = gokzg4844.NewContext4096Secure()
var NumGoRoutines = 0

func TestInsertionCircuit(t *testing.T) {
	ids := generateRandomIdentities(4096)
	idsBytes := bigIntsToBytes(ids)

	blob := bytesToBlob(idsBytes)
	commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
	require.NoError(t, err)

	// TODO is this necessary
	proof, err := ctx.ComputeBlobKZGProof(blob, commitment, NumGoRoutines)
	require.NoError(t, err)
	err = ctx.VerifyBlobKZGProof(blob, commitment, proof)
	require.NoError(t, err)
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

// bytesToBlob copies the contents of idsBytes into a Blob
func bytesToBlob(idsBytes []byte) *gokzg4844.Blob {
	var blob gokzg4844.Blob
	copy(blob[:], idsBytes)
	return &blob
}

// bytesToBigIntModGNARKBN254 converts a slice of bytes to a *big.Int and reduces it by the BN254 modulus using gnark-crypto
func bytesToBigInt(b []byte) *big.Int {
	n := new(big.Int).SetBytes(b)
	// Get the modulus from gnark-crypto's BN254 field
	modulus := bn254fr.Modulus()
	// Reduce n modulo BN254 prime using gnark-crypto's modulus
	return n.Mod(n, modulus)
}
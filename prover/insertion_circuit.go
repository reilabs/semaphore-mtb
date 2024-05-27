package prover

import (
	"math"
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"

	"worldcoin/gnark-mbu/prover/barycentric"
	"worldcoin/gnark-mbu/prover/keccak"
	"worldcoin/gnark-mbu/prover/poseidon"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

type InsertionMbuCircuit struct {
	// public inputs
	InputHash frontend.Variable `gnark:",public"`
	ExpectedEvaluation frontend.Variable `gnark:",public"`
	Commitment4844     frontend.Variable `gnark:",public"`
	StartIndex         frontend.Variable `gnark:",public"`
	PreRoot            frontend.Variable `gnark:",public"`
	PostRoot           frontend.Variable `gnark:",public"`

	// private inputs
	IdComms      []frontend.Variable   `gnark:"input"`
	MerkleProofs [][]frontend.Variable `gnark:"input"`

	Depth     int
	// TODO should these guys be here?
	// Omega            big.Int // ω
	// PolynomialDegree int
}

// getMerkleTreeRoot calculates the Merkle Tree root repeatedly hashing pairs of elements in the input slice until only
// one element remains. This process effectively builds a binary tree of hashes, where each level of the tree is half
// the size of the level below it.
// At the end or the process the function returns the root value of such constructed Merkle Tree.
func getMerkleTreeRoot(api frontend.API, input []frontend.Variable) frontend.Variable {
	temp := input[:]
	for len(temp) > 1 {
		newInput := make([]frontend.Variable, len(temp)/2)
		for i := range newInput {
			newInput[i] = abstractor.Call(
				api, poseidon.Poseidon2{
					In1: temp[2*i],
					In2: temp[2*i+1],
				},
			)
		}
		temp = newInput
	}
	return temp[0]
}

type Fr = emulated.BLS12381Fr

const polynomialDegree = 4096

func computeOmegaToI() (*big.Int, *big.Int) {
	// This function assumes BLS12381Fr field and polynomial degree 4096
	modulus, _ := new(big.Int).SetString(
		"52435875175126190479447740508185965837690552500527637822603658699938581184513", 10,
	)

	// For polynomial degree d = 4096 = 2^12:
	// ω^(2^32) = ω^(2^20 * 2^12)
	// Calculate ω^20 starting with root of unity of 2^32 degree
	omega, _ := new(big.Int).SetString(
		"10238227357739495823651030575849232062558860180284477541189508159991286009131", 10,
	)
	polynomialDegreeExp := int(math.Log2(float64(polynomialDegree)))
	omegaExpExp := 32 // ω^(2^32)
	for range omegaExpExp - polynomialDegreeExp {
		omega.Mul(omega, omega)
		omega.Mod(omega, modulus)
	}

	return omega, modulus
}

func evaluatePolynomial(
	api frontend.API, interpolatingPoints []frontend.Variable, pointOfEvaluation frontend.Variable,
) (evaluationValue frontend.Variable) {
	startingOmega, _ := computeOmegaToI()
	omegasToI := make([]emulated.Element[Fr], polynomialDegree)
	omegaToI := big.NewInt(1)
	for i := range polynomialDegree {
		omegasToI[i] = emulated.ValueOf[Fr](omegaToI)
		omegaToI.Mul(omegaToI, startingOmega)
	}

	field, err := emulated.NewField[Fr](api)
	if err != nil {
		return err
	}

	x := *field.FromBits(api.ToBinary(pointOfEvaluation)...)
	w := make([]emulated.Element[Fr], len(interpolatingPoints))
	for i, p := range interpolatingPoints {
		w[i] = *field.FromBits(api.ToBinary(p)...)
	}
	y := barycentric.CalculateBarycentricFormula(field, omegasToI, w, x)

	evaluationValue = api.FromBinary(field.ToBits(&y)...)
	return
}

func (circuit *InsertionMbuCircuit) Define(api frontend.API) error {
	rootHash := getMerkleTreeRoot(api, circuit.IdComms)
	api.AssertIsEqual(circuit.InputHash, rootHash)

	var bits []frontend.Variable
	// We convert all the inputs to the keccak hash to use big-endian (network) byte
	// ordering so that it agrees with Solidity. This ensures that we don't have to
	// perform the conversion inside the contract and hence save on gas.
	bitsHash := abstractor.Call1(
		api, ToReducedBigEndian{
			Variable: circuit.InputHash,
			Size:     253,  // TODO make sure this length is always right
		},
	)
	bits = append(bits, bitsHash...)
	bitsCommitment := abstractor.Call1(
		api, ToReducedBigEndian{
			Variable: circuit.Commitment4844,
			Size:     256,
		},
	)
	bits = append(bits, bitsCommitment...)

	// Compute Fiat-Shamir challenge of input hash and 4844 commitment
	hash, err := keccak.Keccak256(api, bits)
	if err != nil {
		return err
	}
	challenge := abstractor.Call(api, FromBinaryBigEndian{Variable: hash})

	// Calculate evaluation of polynomial interpolated by identities in the point x=challenge
	evaluation := evaluatePolynomial(api, circuit.IdComms, challenge)
	api.AssertIsEqual(circuit.ExpectedEvaluation, evaluation)

	// Actual batch merkle proof verification.
	root := abstractor.Call(
		api, InsertionProof{
			StartIndex: circuit.StartIndex,
			PreRoot:    circuit.PreRoot,
			IdComms:    circuit.IdComms,

			MerkleProofs: circuit.MerkleProofs,

			Depth:     circuit.Depth,
		},
	)

	// Final root needs to match.
	api.AssertIsEqual(root, circuit.PostRoot)

	return nil
}

func ImportInsertionSetup(treeDepth uint32, batchSize uint32, pkPath string, vkPath string) (*ProvingSystem, error) {
	proofs := make([][]frontend.Variable, batchSize)
	for i := 0; i < int(batchSize); i++ {
		proofs[i] = make([]frontend.Variable, treeDepth)
	}
	circuit := InsertionMbuCircuit{
		Depth:        int(treeDepth),
		IdComms:      make([]frontend.Variable, batchSize),
		MerkleProofs: proofs,
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, err
	}

	pk, err := LoadProvingKey(pkPath)

	if err != nil {
		return nil, err
	}

	vk, err := LoadVerifyingKey(vkPath)

	if err != nil {
		return nil, err
	}

	return &ProvingSystem{treeDepth, batchSize, pk, vk, ccs}, nil
}

package prover

import (
	"io"
	"strconv"
	"worldcoin/gnark-mbu/prover/poseidon"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/abstractor"
)

type Proof struct {
	Proof groth16.Proof
}

type ProvingSystem struct {
	TreeDepth        uint32
	BatchSize        uint32
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
}

const emptyLeaf = 0

type bitPatternLengthError struct {
	actualLength int
}

func (e *bitPatternLengthError) Error() string {
	return "Bit pattern length was " + strconv.Itoa(e.actualLength) + " not a total number of bytes"
}

// ProofRound gadget generates the ParentHash
type ProofRound struct {
	Direction frontend.Variable
	Hash      frontend.Variable
	Sibling   frontend.Variable
}

func (gadget ProofRound) DefineGadget(api abstractor.API) []frontend.Variable {
	api.AssertIsBoolean(gadget.Direction)
	d1 := api.Select(gadget.Direction, gadget.Hash, gadget.Sibling)
	d2 := api.Select(gadget.Direction, gadget.Sibling, gadget.Hash)
	sum := api.Call(poseidon.Poseidon2{In1: d1, In2: d2})[0]
	return []frontend.Variable{sum}
}

// VerifyProof recovers the Merkle Tree using Proof[] and Path[] and returns the tree Root
// Proof[0] corresponds to the Leaf which is why len(Proof) === len(Path) + 1
type VerifyProof struct {
	Proof []frontend.Variable
	Path  []frontend.Variable
}

func (gadget VerifyProof) DefineGadget(api abstractor.API) []frontend.Variable {
	sum := gadget.Proof[0]
	for i := 1; i < len(gadget.Proof); i++ {
		sum = api.Call(ProofRound{Direction: gadget.Path[i-1], Hash: gadget.Proof[i], Sibling: sum})[0]
	}
	return []frontend.Variable{sum}
}

type InsertionRound struct {
	Index    frontend.Variable
	Item     frontend.Variable
	PrevRoot frontend.Variable
	Proof    []frontend.Variable

	Depth int
}

func (gadget InsertionRound) DefineGadget(api abstractor.API) []frontend.Variable {
	currentPath := api.ToBinary(gadget.Index, gadget.Depth)

	// len(circuit.MerkleProofs) === circuit.BatchSize
	// len(circuit.MerkleProofs[i]) === circuit.Depth
	// len(circuit.IdComms) === circuit.BatchSize
	// Verify proof for empty leaf.
	proof := append([]frontend.Variable{emptyLeaf}, gadget.Proof[:]...)
	root := api.Call(VerifyProof{Proof: proof, Path: currentPath})[0]
	api.AssertIsEqual(root, gadget.PrevRoot)

	// Verify proof for idComm.
	proof = append([]frontend.Variable{gadget.Item}, gadget.Proof[:]...)
	root = api.Call(VerifyProof{Proof: proof, Path: currentPath})[0]

	return []frontend.Variable{root}
}

type InsertionProof struct {
	StartIndex frontend.Variable
	PreRoot    frontend.Variable
	IdComms    []frontend.Variable

	MerkleProofs [][]frontend.Variable

	BatchSize int
	Depth     int
}

func (gadget InsertionProof) DefineGadget(api abstractor.API) []frontend.Variable {
	prevRoot := gadget.PreRoot

	// Individual insertions.
	for i := 0; i < gadget.BatchSize; i += 1 {
		currentIndex := api.Add(gadget.StartIndex, i)
		prevRoot = api.Call(InsertionRound{
			Index: currentIndex,
			Item: gadget.IdComms[i],
			PrevRoot: prevRoot,
			Proof: gadget.MerkleProofs[i],
			Depth: gadget.Depth,
		})[0]
	}

	return []frontend.Variable{prevRoot}
}

type DeletionRound struct {
	Root          frontend.Variable
	Index         frontend.Variable
	Item          frontend.Variable
	MerkleProofs  []frontend.Variable

	Depth         int
}

func (gadget DeletionRound) DefineGadget(api abstractor.API) []frontend.Variable {
	// We verify that the Leaf belongs to the Merkle Tree by verifying that the computed root
	// matches gadget.Root. Then, we return the root computed with Leaf being empty.
	currentPath := api.ToBinary(gadget.Index, gadget.Depth)

	// Verify proof for Item.
	root := api.Call(VerifyProof{append([]frontend.Variable{gadget.Item}, gadget.MerkleProofs[:]...), currentPath})[0]
	api.AssertIsEqual(root, gadget.Root)

	// Verify proof for empty leaf.
	root = api.Call(VerifyProof{append([]frontend.Variable{emptyLeaf}, gadget.MerkleProofs[:]...), currentPath})[0]

	return []frontend.Variable{root}
}

type DeletionProof struct {
	DeletionIndices []frontend.Variable
	PreRoot         frontend.Variable
	IdComms         []frontend.Variable
	MerkleProofs    [][]frontend.Variable

	BatchSize int
	Depth     int
}

func (gadget DeletionProof) DefineGadget(api abstractor.API) []frontend.Variable {
	// Actual batch merkle proof verification.
	root := gadget.PreRoot

	// Individual deletions.
	for i := 0; i < gadget.BatchSize; i += 1 {
		// Set root for next iteration.
		root = api.Call(DeletionRound{
			Root: root,
			Index: gadget.DeletionIndices[i],
			Item: gadget.IdComms[i],
			MerkleProofs: gadget.MerkleProofs[i],
			Depth: gadget.Depth,
		})[0]
	}

	return []frontend.Variable{root}
}

// SwapBitArrayEndianness Swaps the endianness of the bit pattern in bits,
// returning the result in newBits.
//
// It does not introduce any new circuit constraints as it simply moves the
// variables (that will later be instantiated to bits) around in the slice to
// change the byte ordering. It has been verified to be a constraint-neutral
// operation, so please maintain this invariant when modifying it.
//
// Raises a bitPatternLengthError if the length of bits is not a multiple of a
// number of bytes.
func SwapBitArrayEndianness(bits []frontend.Variable) (newBits []frontend.Variable, err error) {
	bitPatternLength := len(bits)

	if bitPatternLength%8 != 0 {
		return nil, &bitPatternLengthError{bitPatternLength}
	}

	for i := bitPatternLength - 8; i >= 0; i -= 8 {
		currentBytes := bits[i : i+8]
		newBits = append(newBits, currentBytes...)
	}

	if bitPatternLength != len(newBits) {
		return nil, &bitPatternLengthError{len(newBits)}
	}

	return newBits, nil
}

// ToBinaryBigEndian converts the provided variable to the corresponding bit
// pattern using big-endian byte ordering.
//
// Raises a bitPatternLengthError if the number of bits in variable is not a
// whole number of bytes.
func ToBinaryBigEndian(variable frontend.Variable, size int, api frontend.API) (bitsBigEndian []frontend.Variable, err error) {
	bitsLittleEndian := api.ToBinary(variable, size)
	return SwapBitArrayEndianness(bitsLittleEndian)
}

// FromBinaryBigEndian converts the provided bit pattern that uses big-endian
// byte ordering to a variable that uses little-endian byte ordering.
//
// Raises a bitPatternLengthError if the number of bits in `bitsBigEndian` is not
// a whole number of bytes.
func FromBinaryBigEndian(bitsBigEndian []frontend.Variable, api frontend.API) (variable frontend.Variable, err error) {
	bitsLittleEndian, err := SwapBitArrayEndianness(bitsBigEndian)
	if err != nil {
		return nil, err
	}

	return api.FromBinary(bitsLittleEndian...), nil
}

func toBytesLE(b []byte) []byte {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return b
}

func (ps *ProvingSystem) ExportSolidity(writer io.Writer) error {
	return ps.VerifyingKey.ExportSolidity(writer)
}
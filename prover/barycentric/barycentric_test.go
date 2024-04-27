package barycentric

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	"worldcoin/gnark-mbu/prover/field_utils"
)

type BarycentricCircuit[T emulated.FieldParams] struct {
	Omega big.Int // ω
	PolynomialDegree int

	// Inputs (private)
	YNodes      []frontend.Variable  // len(YNodes) == PolynomialDegree
	TargetPoint frontend.Variable

	// Output
	InterpolatedPoint frontend.Variable `gnark:",public"`
}

func (circuit *BarycentricCircuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}

	api.AssertIsEqual(len(circuit.YNodes), circuit.PolynomialDegree)

	// Convert frontend.Variables to field elements
	yNodes := make([]emulated.Element[T], circuit.PolynomialDegree)
	omegasToI := make([]emulated.Element[T], circuit.PolynomialDegree)
	omegaToI := big.NewInt(1)
	for i := range circuit.PolynomialDegree {
		omegasToI[i] = emulated.ValueOf[T](omegaToI)
		omegaToI.Mul(omegaToI, &circuit.Omega)

		yNodes[i] = field_utils.VariableToFieldElement(field, api, circuit.YNodes[i])
	}
	targetPoint := field_utils.VariableToFieldElement(field, api, circuit.TargetPoint)
	interpolatedPoint := field_utils.VariableToFieldElement(field, api, circuit.InterpolatedPoint)

	// Method under test
	interpolatedPointCalculated := CalculateBarycentricFormula[T](field, omegasToI, yNodes, targetPoint)

	field.AssertIsEqual(&interpolatedPoint, &interpolatedPointCalculated)

	return nil
}

func TestCalculateBarycentricFormula(t *testing.T) {
	assert := test.NewAssert(t)

	modulus, ok := new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	assert.True(ok)
	omega, _ := new(big.Int).SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131",
		10)

	// we have: foo^(2^32) = 1
	// (foo^2)^(2^31) = foo ^ (2 * 2^31) = foo ^ (2 ^ 32) = 1
	// (foo^(2^30))^4 = foo ^ (4 * 2 ^ 30) = foo ^ (2^2 * 2^30) = foo ^ (2 ^ 32) = 1

	for range 30 {
		omega.Mul(omega, omega)
		omega.Mod(omega, modulus)
	}

	circuit := BarycentricCircuit[emulated.BLS12381Fr]{
		Omega:  *omega,
		PolynomialDegree: 4,
		YNodes: make([]frontend.Variable, 4),
	}

	interpolatedBI := make([]big.Int, 4)
	for i := range 4 {
		interpolatedBI[i] = *new(big.Int).Exp(omega, big.NewInt(int64(i*3)), modulus)
	}

	interpolated := make([]frontend.Variable, 4)
	for i := range 4 {
		interpolated[i] = interpolatedBI[i]
	}

	assignment := BarycentricCircuit[emulated.BLS12381Fr]{
		YNodes:            interpolated,
		TargetPoint:       3,
		InterpolatedPoint: 27,
	}

	assert.CheckCircuit(
		&circuit,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BLS12_381),
		test.WithValidAssignment(&assignment),
	)
}

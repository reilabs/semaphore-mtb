package barycentric

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func variableToFieldElement[T emulated.FieldParams](
	field *emulated.Field[T],
	api frontend.API,
	variable frontend.Variable,
) emulated.Element[T] {
	return *field.FromBits(api.ToBinary(variable)...)
}

type Circuit[T emulated.FieldParams] struct {
	Omega big.Int // ω

	// Inputs (private)
	YNodes      []frontend.Variable
	TargetPoint frontend.Variable

	// Output
	InterpolatedPoint frontend.Variable `gnark:",public"`
}

func (circuit *Circuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}

	api.AssertIsEqual(len(circuit.YNodes), polynomialDegree)

	// Convert frontend.Variables to field elements
	yNodesFe := make([]emulated.Element[T], len(circuit.YNodes))
	omegasToIFe := make([]emulated.Element[T], polynomialDegree)
	omegaToI := big.NewInt(1)
	for i := range polynomialDegree {
		omegasToIFe[i] = emulated.ValueOf[T](omegaToI)
		omegaToI.Mul(omegaToI, &circuit.Omega)

		yNodesFe[i] = variableToFieldElement(field, api, circuit.YNodes[i])
	}
	targetPointFe := variableToFieldElement(field, api, circuit.TargetPoint)
	interpolatedPointFe := variableToFieldElement(field, api, circuit.InterpolatedPoint)

	interpolatedPointCalculated := calculateBarycentricFormula[T](field, omegasToIFe, yNodesFe, targetPointFe)

	field.AssertIsEqual(&interpolatedPointFe, &interpolatedPointCalculated)

	return nil
}

// TODO this may be big.int in circuit
// TODO this will be 4096
const polynomialDegree = 4

func calculateBarycentricFormula[T emulated.FieldParams](
	field *emulated.Field[T],
	omegasToI, yNodes []emulated.Element[T],
	targetPoint emulated.Element[T],
) emulated.Element[T] {

	// TODO we're using field.Exp() here which works on variable exponent.
	// We probably can simplify this to constant exponent for cheaper calculations.

	// First term: (z^d - 1) / d
	d := emulated.ValueOf[T](polynomialDegree)
	zToD := field.Exp(&targetPoint, &d)
	firstTerm := *field.Sub(zToD, field.One())
	firstTerm = *field.Div(&firstTerm, &d)

	// Second term: Σ(f_i * ω^i)/(z - ω^i) from i=0 to d-1
	secondTerm := field.Zero()
	for i := range polynomialDegree {
		numerator := *field.Mul(&yNodes[i], &omegasToI[i])
		denominator := *field.Sub(&targetPoint, &omegasToI[i])
		term := *field.Div(&numerator, &denominator)
		secondTerm = field.Add(secondTerm, &term)
	}

	return *field.Mul(&firstTerm, secondTerm)
}

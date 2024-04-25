package barycentric

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Circuit[T emulated.FieldParams] struct {
	// Inputs (private)
	XNodes      []frontend.Variable
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

	// Convert frontend.Variables to field elements
	api.AssertIsEqual(len(circuit.XNodes), len(circuit.YNodes))
	xNodesFe := make([]emulated.Element[T], len(circuit.XNodes))
	yNodesFe := make([]emulated.Element[T], len(circuit.YNodes))
	for i := range circuit.XNodes {
		xNodesFe[i] = variableToFieldElement(field, api, circuit.XNodes[i])
		yNodesFe[i] = variableToFieldElement(field, api, circuit.YNodes[i])
	}
	targetPointFe := variableToFieldElement(field, api, circuit.TargetPoint)
	interpolatedPointFe := variableToFieldElement(field, api, circuit.InterpolatedPoint)

	weights := calculateWeights[T](field, xNodesFe)
	interpolatedPointCalculated := barycentricPolynomial[T](field, weights, xNodesFe, yNodesFe, targetPointFe)

	field.AssertIsEqual(&interpolatedPointFe, &interpolatedPointCalculated)

	return nil
}

func variableToFieldElement[T emulated.FieldParams](
	field *emulated.Field[T],
	api frontend.API,
	variable frontend.Variable,
) emulated.Element[T] {
	return *field.FromBits(api.ToBinary(variable)...)
}

func calculateWeights[T emulated.FieldParams](field *emulated.Field[T], xNodes []emulated.Element[T]) []emulated.Element[T] {
	n := len(xNodes)
	weights := make([]emulated.Element[T], n)

	for j := range n {
		w := emulated.ValueOf[T](1)
		for k := 0; k < n; k++ {
			if k != j {
				w = *field.Div(&w, field.Sub(&xNodes[j], &xNodes[k]))
			}
		}
		weights[j] = w
	}

	return weights
}

func barycentricPolynomial[T emulated.FieldParams](
	field *emulated.Field[T],
	weights, xNodes, yNodes []emulated.Element[T],
	targetPoint emulated.Element[T],
) emulated.Element[T] {
	n := len(xNodes)
	numerator := emulated.ValueOf[T](0)
	denominator := emulated.ValueOf[T](0)

	for j := range n {
		temp := field.Div(&weights[j], field.Sub(&targetPoint, &xNodes[j]))
		numerator = *field.Add(&numerator, field.Mul(temp, &yNodes[j]))
		denominator = *field.Add(&denominator, temp)
	}

	return *field.Div(&numerator, &denominator)
}

type CircuitDankrad[T emulated.FieldParams] struct {
	Omega big.Int // ω

	// Inputs (private)
	YNodes      []emulated.Element[]
	TargetPoint frontend.Variable

	// Output
	InterpolatedPoint frontend.Variable `gnark:",public"`
}

func (circuit *CircuitDankrad[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}

	api.AssertIsEqual(len(circuit.YNodes), polynomialDegree)

	// Convert frontend.Variables to field elements
	yNodesFe := make([]emulated.Element[T], len(circuit.YNodes))
	for i, node := range circuit.YNodes {
		yNodesFe[i] = variableToFieldElement(field, api, node)
	}
	wFe := variableToFieldElement(field, api, circuit.Omega)
	targetPointFe := variableToFieldElement(field, api, circuit.TargetPoint)
	interpolatedPointFe := variableToFieldElement(field, api, circuit.InterpolatedPoint)

	interpolatedPointCalculated := dankradBarycentricPolynomial[T](field, wFe, yNodesFe, targetPointFe)

	field.AssertIsEqual(&interpolatedPointFe, &interpolatedPointCalculated)

	return nil
}

// TODO this may be big.int in circuit
// TODO this will be 4096
const polynomialDegree = 4

func dankradBarycentricPolynomial[T emulated.FieldParams](
	field *emulated.Field[T],
	omega emulated.Element[T],
	yNodes []emulated.Element[T],
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
	for degree := range polynomialDegree {
		i := emulated.ValueOf[T](degree)
		omegaToI := field.Exp(&omega, &i)
		numerator := *field.Mul(&yNodes[degree], omegaToI)
		denominator := *field.Sub(&targetPoint, omegaToI)
		term := *field.Div(&numerator, &denominator)
		secondTerm = field.Add(secondTerm, &term)
	}

	return *field.Mul(&firstTerm, secondTerm)
}

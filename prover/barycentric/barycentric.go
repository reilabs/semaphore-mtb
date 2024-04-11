package barycentric

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Circuit[T emulated.FieldParams] struct {
	// Inputs (private)
	XNodes []frontend.Variable
	YNodes []frontend.Variable
	TargetPoint frontend.Variable

	// Output
	InterpolatedPoint frontend.Variable `gnark:",public"`
}

func (circuit *Circuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}

	xNodesFe := make([]emulated.Element[T], len(circuit.XNodes))
	for xNodeId, xNode := range circuit.XNodes {
		xNodesFe[xNodeId] = variableToFieldElement(field, api, xNode)
	}

	yNodesFe := make([]emulated.Element[T], len(circuit.XNodes))
	for yNodeId, yNode := range circuit.YNodes {
		yNodesFe[yNodeId] = variableToFieldElement(field, api, yNode)
	}

	interpolatedPointFe := variableToFieldElement(field, api, circuit.InterpolatedPoint)


	weights := calculateWeights[T](field, xNodesFe)
	interpolatedPoint := barycentricPolynomial[T](field, xNodesFe, yNodesFe, weights, interpolatedPointFe)

	field.AssertIsEqual(&interpolatedPointFe, &interpolatedPoint)

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

	for j := 0; j < n; j++ {
		// TODO
		// If x matches one of the interpolation nodes exactly, return the corresponding y value immediately
		// if x == xNodes[j] {
		// 	return yNodes[j]
		// }
		w := emulated.ValueOf[T](1)
		for k := 0; k < n; k++ {
			if k != j {
				sub := field.Sub(&xNodes[j], &xNodes[k])
				w = *field.Mul(&w, field.Inverse(sub))
			}
		}
		weights[j] = w
	}

	return weights
}

func barycentricPolynomial[T emulated.FieldParams](
	field *emulated.Field[T],
	xNodes, yNodes, weights []emulated.Element[T],
	targetPoint emulated.Element[T],
	) emulated.Element[T] {
	n := len(xNodes)
	numerator := emulated.ValueOf[T](0)
	denominator := emulated.ValueOf[T](0)

	for j := 0; j < n; j++ {
		temp := field.Div(&weights[j], field.Sub(&targetPoint, &xNodes[j]))
		numerator = *field.Add(&numerator, field.Mul(temp, &yNodes[j]))
		denominator = *field.Add(&denominator, temp)
	}

	return *field.Div(&numerator, &denominator)
}
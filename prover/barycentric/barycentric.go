package barycentric

import (
	"github.com/consensys/gnark/std/math/emulated"
)

// TODO this may be big.int in circuit
// TODO this will be 4096
const polynomialDegree = 4

func CalculateBarycentricFormula[T emulated.FieldParams](
	field *emulated.Field[T],
	omegasToI, yNodes []emulated.Element[T],
	targetPoint emulated.Element[T],
) emulated.Element[T] {

	// TODO we're using field.Exp() here which works on variable exponent.
	// We probably can simplify this to constant exponent for cheaper calculations.

	// First term: (z^d - 1) / d
	zToD := Exp(field, &targetPoint, polynomialDegree)
	firstTerm := *field.Sub(zToD, field.One())
	d := emulated.ValueOf[T](polynomialDegree)
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

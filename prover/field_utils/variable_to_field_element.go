package field_utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// VariableToFieldElement converts given variable to element of the given field.
//
// field - target prime field.
// api - Gnark API used to manipulate frontend variables.
// variable - variable to be converted.
func VariableToFieldElement[T emulated.FieldParams](
	field *emulated.Field[T],
	api frontend.API,
	variable frontend.Variable,
) emulated.Element[T] {
	return *field.FromBits(api.ToBinary(variable)...)
}
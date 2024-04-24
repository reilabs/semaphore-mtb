package barycentric

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type BaseTo10Circuit[T emulated.FieldParams] struct {
	Base frontend.Variable
	// Exp = 10
	Res frontend.Variable
}

func (c *BaseTo10Circuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}

	x := variableToFieldElement[T](field, api, c.Base)
	y := 10
	z := variableToFieldElement[T](field, api, c.Res)

	field.AssertIsEqual(
		exp[T](field, &x, y),
		&z)

	return nil
}

func TestExp(t *testing.T) {
	assert := test.NewAssert(t)


	assignment := BaseTo10Circuit[emulated.BLS12381Fr]{
		2,
		1024,
	}

	assert.CheckCircuit(
		&BaseTo10Circuit[emulated.BLS12381Fr]{},
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BLS12_381),
		test.WithValidAssignment(&assignment),
	)
}
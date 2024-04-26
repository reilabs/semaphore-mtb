package barycentric

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ExpCircuit[T emulated.FieldParams] struct {
	Base frontend.Variable
	Exp int
	Res frontend.Variable
}

func (c *ExpCircuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}

	base := variableToFieldElement[T](field, api, c.Base)
	res := variableToFieldElement[T](field, api, c.Res)

	// Function under test
	calculatedRes := Exp[T](field, &base, c.Exp)

	field.AssertIsEqual(calculatedRes, &res)

	return nil
}

func randomPower() (int, int, *big.Int) {
	base := rand.Intn(16)
	exponent := rand.Intn(16)
	result := new(big.Int).Exp(big.NewInt(int64(base)), big.NewInt(int64(exponent)), nil)
	return base, exponent, result
}
func TestExp(t *testing.T) {
	assert := test.NewAssert(t)

	for range 16 {  // Arbitrary choice of number of tests
		base, exp, want := randomPower()
		circuit := ExpCircuit[emulated.BLS12381Fr]{
			Exp: exp,
		}

		assignment := ExpCircuit[emulated.BLS12381Fr]{
			Base: base,
			Res: want,
		}

		t.Run(
			fmt.Sprintf("%d^%d", base, exp),
			func(t *testing.T) {
				assert.CheckCircuit(
					&circuit,
					test.WithBackends(backend.GROTH16),
					test.WithCurves(ecc.BN254),
					test.WithValidAssignment(&assignment),
				)
			},
		)
	}
}

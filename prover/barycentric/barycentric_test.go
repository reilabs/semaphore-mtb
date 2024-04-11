package barycentric

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestBarycentricCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := Circuit[emulated.BLS12381Fr]{
		XNodes:            make([]frontend.Variable, 3),
		YNodes:            make([]frontend.Variable, 3),
	}

	assignment := Circuit[emulated.BLS12381Fr]{
		XNodes:            []frontend.Variable{1, 2, 3},
		YNodes:            []frontend.Variable{2, 3, 4},
		TargetPoint:       2,
		InterpolatedPoint: 3,
	}

	assert.CheckCircuit(
		&circuit,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BLS12_381),
		test.WithValidAssignment(&assignment),
		)
}

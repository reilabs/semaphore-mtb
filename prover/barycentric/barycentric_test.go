package barycentric

import (
	"fmt"
	"math/big"
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
		XNodes: make([]frontend.Variable, 4),
		YNodes: make([]frontend.Variable, 4),
	}

	assignment := Circuit[emulated.BLS12381Fr]{
		XNodes:            []frontend.Variable{1, 2, 4, 8},
		YNodes:            []frontend.Variable{1, 8, 64, 512},
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

func barycentricFormula(rou, modulus, target *big.Int, interpolated []big.Int) *big.Int {
	d := big.NewInt(int64(len(interpolated)))

	// First term
	firstTerm := new(big.Int).Exp(target, d, modulus)
	firstTerm.Sub(firstTerm, big.NewInt(1))
	firstTerm.Div(firstTerm, d)

	// Second term
	secondTerm := big.NewInt(0)
	for degree := range len(interpolated) {
		i := big.NewInt(int64(degree))
		omegaToI := new(big.Int).Exp(rou, i, modulus)
		numerator := new(big.Int).Mul(&interpolated[degree], omegaToI)
		denominator := new(big.Int).Sub(target, omegaToI)
		denominatorInverse := new(big.Int).ModInverse(denominator, modulus)
		term := new(big.Int).Mul(numerator, denominatorInverse)
		secondTerm.Add(secondTerm, term)
	}

	res := new(big.Int).Mul(firstTerm, secondTerm)
	return res.Mod(res, modulus)
}

func TestDankradBarycentricCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	modulus, ok := new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	assert.True(ok)
	modulus2, ok := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	assert.True(ok)
	assert.Equal(*modulus, *modulus2)

	foo, _ := new(big.Int).SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131", 10)

	// we have: foo^(2^32) = 1
	// (foo^2)^(2^31) = foo ^ (2 * 2^31) = foo ^ (2 ^ 32) = 1
	// (foo^(2^30))^4 = foo ^ (4 * 2 ^ 30) = foo ^ (2^2 * 2^30) = foo ^ (2 ^ 32) = 1

	for range 30 {
		//fmt.Println(foo)
		foo.Mul(foo, foo)
		foo.Mod(foo, modulus)
	}
	fmt.Println(foo)

	circuit := CircuitDankrad[emulated.BLS12381Fr]{
		Omega:  *foo,
		YNodes: make([]frontend.Variable, 4),
	}

	interpolatedBI := make([]big.Int, 4)
	for i := range 4 {
		interpolatedBI[i] = *new(big.Int).Exp(foo, big.NewInt(int64(i*3)), modulus)
	}

	fmt.Println(barycentricFormula(foo, modulus, big.NewInt(3), interpolatedBI))

	interpolated := make([]frontend.Variable, 4)
	for i := range 4 {
		interpolated[i] = interpolatedBI[i]
	}

	assignment := CircuitDankrad[emulated.BLS12381Fr]{
		YNodes:            interpolated,
		TargetPoint:       3,
		InterpolatedPoint: 27,
	}

	assert.CheckCircuit(
		&circuit,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BN254),
		test.WithValidAssignment(&assignment),
	)
}

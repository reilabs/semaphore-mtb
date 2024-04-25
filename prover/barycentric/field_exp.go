package barycentric

import "github.com/consensys/gnark/std/math/emulated"

func exp[T emulated.FieldParams](field *emulated.Field[T], base *emulated.Element[T], exp int) *emulated.Element[T] {
	res := field.One()

	for _ = range exp {
		res = field.Mul(res, base)
	}

	return res
}

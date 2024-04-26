package barycentric

import "github.com/consensys/gnark/std/math/emulated"

func Exp[T emulated.FieldParams](field *emulated.Field[T], base *emulated.Element[T],
	exponent int) *emulated.Element[T] {
	res := field.One()
	for exponent > 0 {
		if exponent%2 == 1 {
			res = field.Mul(res, base)
		}
		base = field.Mul(base, base)
		exponent /= 2
	}
	return res
}

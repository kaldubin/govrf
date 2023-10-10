package curve

import (
	"math/big"

	"filippo.io/edwards25519"
)

type Ed25519Point struct {
	point edwards25519.Point
}

func (ed *Ed25519Point) Add(y Ed25519Point) {
	ed.point.Add(&ed.point, &y.point)
}

func (ed *Ed25519Point) Mul(y *big.Int) {
	var scalar = edwards25519.NewScalar()
	scalar.SetUniformBytes(y.Bytes())
	ed.point.ScalarMult(scalar, &ed.point)
}

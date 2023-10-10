package curve

import (
	"crypto/elliptic"
	"math/big"
)

type P256Point struct {
	curve elliptic.Curve
	x, y  *big.Int
}

func (ptx *P256Point) Add(pty *P256Point) {
	ptx.x, ptx.y = ptx.curve.Add(ptx.x, ptx.y, pty.x, pty.y)
}

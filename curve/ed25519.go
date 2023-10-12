package curve

import (
	"crypto/sha512"
	"hash"
	"math/big"

	"example.com/temp/util"
	"filippo.io/edwards25519"
)

type Ed25519 struct {
	prime, order, l_maj, m *big.Int
	hash                   hash.Hash
}

func NewEd25519() Ed25519 {
	return Ed25519{
		prime: big.NewInt(0),
		order: big.NewInt(0),
		l_maj: big.NewInt(0),
		m:     big.NewInt(0),
		hash:  sha512.New(),
	}
}

func (ed Ed25519) elligator2(u *big.Int) (*big.Int, *big.Int) {
	// x1 = -(J / K) * inv0(1 + Z * u^2)
	var x1 *big.Int
	var x11 *big.Int
	x1.Div(j_maj, k_maj)
	x1.Neg(x11)
	x11.Exp(u, big.NewInt(2), ed.prime)
	x11.Mul(x11, z_maj)
	x11 = util.Inv0(x11.Add(x11, big.NewInt(1)), ed.order)
	x1.Mul(x1, x11)

	// If x1 == 0, set x1 = -(J / K)
	if x1.Cmp(big.NewInt(0)) == 0 {
		x1.Div(j_maj, k_maj)
		x1.Neg(x1)
	}

	// gx1 = x1^3 + (J / K) * x1^2 + x1 / K^2
	var gx1 *big.Int
	gx1.Exp(x1, big.NewInt(3), ed.prime)
	var gx11 *big.Int
	gx11.Div(j_maj, k_maj)
	var gx12 *big.Int
	gx12.Exp(x1, big.NewInt(2), ed.prime)
	gx11.Mul(gx11, gx12)
	gx12.Exp(k_maj, big.NewInt(2), ed.prime)
	gx12.Div(x1, gx12)
	gx11.Add(gx11, gx12)
	gx1.Add(gx11, gx1)

	// x2 = -x1 - (J / K)
	var x2 *big.Int
	x2.Div(j_maj, k_maj)
	x2.Neg(x2)
	var x21 *big.Int
	x21.Neg(x1)
	x2.Add(x21, x2)

	// gx2 = x2^3 + (J / K) * x2^2 + x2 / K^2
	var gx2 *big.Int
	gx2.Exp(x2, big.NewInt(3), ed.prime)
	var gx21 *big.Int
	gx21.Div(j_maj, k_maj)
	var gx22 *big.Int
	gx22.Exp(x2, big.NewInt(2), ed.prime)
	gx21.Mul(gx21, gx22)
	gx22.Exp(k_maj, big.NewInt(2), ed.prime)
	gx22.Div(x2, gx22)
	gx21.Add(gx21, gx22)
	gx2.Add(gx21, gx2)

	//If is_square(gx1), set x = x1, y = sqrt(gx1) with sgn0(y) == 1
	//Else set x = x2, y = sqrt(gx2) with sgn0(y) == 0.
	var x, y *big.Int
	if util.IsSquare(gx1, ed.order) {
		x = x1
		y.ModSqrt(gx1, ed.prime)
	} else {
		x = x2
		y.ModSqrt(gx2, ed.prime)
	}
	var s, t *big.Int
	s.Mul(x, k_maj)
	t.Mul(y, k_maj)

	return s, t
}

func rational_map(s *big.Int, t *big.Int) (*big.Int, *big.Int) {
	return s, t
}

func (ed Ed25519) Map2Curve(u []big.Int) ([]byte, error) {
	var s, t = elligator2(u[0])
	var v, w = rational_map(s, t)

	var point []byte
	return point, nil
}

func (ed Ed25519) GetOrder() *big.Int {
	return ed.order
}

func (ed Ed25519) GetPrime() *big.Int {
	return ed.prime
}

func (ed Ed25519) GetL() *big.Int {
	return ed.l_maj
}

func (ed Ed25519) GetM() *big.Int {
	return ed.m
}

func (ed Ed25519) GetHashBlockSize() *big.Int {
	return big.NewInt(int64(ed.hash.BlockSize()))
}

func (ed Ed25519) GetHashSize() *big.Int {
	return big.NewInt(int64(ed.hash.Size()))
}

func (ed Ed25519) Hash(input []byte) []byte {
	ed.hash.Reset()
	ed.hash.Write(input)
	return ed.hash.Sum(nil)
}

func (ed Ed25519) Map2Curve(u int) []byte {
	panic(1)
}

func (ed Ed25519) Add(x []byte, y []byte) ([]byte, error) {

	var x_p, errx = edwards25519.NewIdentityPoint().SetBytes(x)
	var y_p, erry = edwards25519.NewIdentityPoint().SetBytes(y)
	if errx != nil {
		return nil, errx
	}
	if erry != nil {
		return nil, erry
	}

	return x_p.Add(x_p, y_p).Bytes(), nil
}

func (ed Ed25519) Subtract(x []byte, y []byte) ([]byte, error) {
	var x_p, errx = edwards25519.NewIdentityPoint().SetBytes(x)
	var y_p, erry = edwards25519.NewIdentityPoint().SetBytes(y)
	if errx != nil {
		return nil, errx
	}
	if erry != nil {
		return nil, erry
	}

	return x_p.Subtract(x_p, y_p).Bytes(), nil
}

func (ed Ed25519) CofactorMultiply(x []byte) ([]byte, error) {
	var x_p, errx = edwards25519.NewIdentityPoint().SetBytes(x)
	if errx != nil {
		return nil, errx
	}

	return x_p.MultByCofactor(x_p).Bytes(), nil
}

func (ed Ed25519) ScalarMultiply(x []byte, k *big.Int) ([]byte, error) {
	var x_p, errx = edwards25519.NewIdentityPoint().SetBytes(x)
	if errx != nil {
		return nil, errx
	}
	var k_byte, errk1 = util.I2SOP(k, 32, "little")
	if errk1 != nil {
		return nil, errk1
	}
	var k_s, errk2 = edwards25519.NewScalar().SetUniformBytes(k_byte)
	if errk2 != nil {
		return nil, errk2
	}

	return x_p.ScalarMult(k_s, x_p).Bytes(), nil
}

func (ed Ed25519) ScalarBaseMultiply(k *big.Int) ([]byte, error) {
	var k_byte, errk1 = util.I2SOP(k, 32, "little")
	if errk1 != nil {
		return nil, errk1
	}
	var k_s, errk2 = edwards25519.NewScalar().SetUniformBytes(k_byte)
	if errk2 != nil {
		return nil, errk2
	}

	return edwards25519.NewGeneratorPoint().ScalarBaseMult(k_s).Bytes(), nil
}

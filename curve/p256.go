package curve

import (
	"encoding/hex"
	"hash"
	"math/big"

	"crypto/elliptic"

	"example.com/temp/util"
	"filippo.io/nistec"
)

type P256 struct {
	prime, order, l_maj, m *big.Int
	hash                   hash.Hash
}

var a_maj = big.NewInt(-3)
var b_maj_os, _ = hex.DecodeString("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
var b_maj = util.OS2IP(b_maj_os, "")
var z_maj = big.NewInt(-10)

// ----------- E2C Interface -----------

// Implement SSWU Method (Simplified Shallue-van de Woestijne-Ulas Method)
func (p256 P256) Map2Curve(u []big.Int) ([]byte, error) {
	var u_0 *big.Int
	if len(u) == 1 {
		u_0 = &u[0]
	}
	// z_maj a field element
	//
	// var tv1 = util.Inv0(p256.z_maj**2 * u**4 + Z * u**2)
	var tv11 *big.Int
	tv11.Exp(z_maj, big.NewInt(2), p256.prime)
	tv11.Mul(tv11, u_0.Exp(u_0, big.NewInt(4), p256.prime))
	var tv12 *big.Int
	tv12.Exp(u_0, big.NewInt(2), p256.prime)
	tv12.Mul(tv12, z_maj)
	tv11.Add(tv11, tv12)
	var tv1 = util.Inv0(tv11, p256.order)

	// x1 = (-B / A) * (1 + tv1)
	var x1 *big.Int
	x1.Neg(b_maj)
	x1.Div(x1, a_maj)
	var x11 *big.Int
	x11.Add(tv1, big.NewInt(1))
	x1.Mul(x1, x11)

	if tv1.Cmp(big.NewInt(0)) == 0 {
		// x1 = B / (Z * A)
		x1.Mul(z_maj, a_maj)
		x1.Div(big.NewInt(1), x1)
		x1.Mul(b_maj, x1)
	}

	// gx1 = x1^3 + A * x1 + B
	var gx1 *big.Int
	gx1.Exp(x1, big.NewInt(3), p256.prime)
	var gx11 *big.Int
	gx11.Mul(a_maj, x1)
	gx1.Add(gx1, gx11)
	gx1.Add(gx1, b_maj)

	// x2 = Z * u^2 * x1
	var x2 *big.Int
	x2.Exp(u_0, big.NewInt(2), p256.prime)
	x2.Mul(x2, z_maj)
	x2.Mul(x2, x1)

	// gx2 = x2^3 + A * x2 + B
	var gx2 *big.Int
	gx2.Exp(x2, big.NewInt(3), p256.prime)
	var gx21 *big.Int
	gx21.Mul(a_maj, x2)
	gx2.Add(gx2, gx21)
	gx2.Add(gx2, b_maj)

	var x, y *big.Int
	if util.IsSquare(gx1, p256.order) {
		x = x1
		y.ModSqrt(gx1, p256.prime)
	} else {
		x = x2
		y.ModSqrt(gx2, p256.prime)
	}

	if util.Sgn0Meq1(u_0).Cmp(util.Sgn0Meq1(y)) != 0 {
		y.Neg(y)
	}

	// If is_square(gx1), set x = x1 and y = sqrt(gx1)
	// Else set x = x2 and y = sqrt(gx2)
	// If sgn0(u) != sgn0(y), set y = -y
	// return (x, y)
	var uell = elliptic.Marshal(elliptic.P256(), x, y)
	var upt, err = nistec.NewP256Point().SetBytes(uell)
	if err != nil {
		return nil, err
	}
	return upt.Bytes(), nil

}

// ----------- CurveParam Interface -----------

func (p256 P256) GetOrder() *big.Int {
	return p256.order
}

func (p256 P256) GetPrime() *big.Int {
	return p256.prime
}

func (p256 P256) GetL() *big.Int {
	return p256.l_maj
}

func (p256 P256) GetM() *big.Int {
	return p256.m
}

func (p256 P256) GetHashBlockSize() *big.Int {
	return big.NewInt(int64(p256.hash.BlockSize()))
}

func (p256 P256) GetHashSize() *big.Int {
	return big.NewInt(int64(p256.hash.Size()))
}

func (p256 P256) Hash(input []byte) []byte {
	p256.hash.Reset()
	p256.hash.Write(input)
	return p256.hash.Sum(nil)
}

// ----------- CurveFunction Interface -----------

var cofactor = [32]byte{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}
var x_p = nistec.NewP256Point()
var y_p = nistec.NewP256Point()

func (p256 *P256) Add(x []byte, y []byte) ([]byte, error) {
	var _, errx = x_p.SetBytes(x)
	if errx != nil {
		return nil, errx
	}
	var _, erry = y_p.SetBytes(y)
	if erry != nil {
		return nil, erry
	}

	return x_p.Add(x_p, y_p).BytesCompressed(), nil
}

func (p256 *P256) Subtract(x []byte, y []byte) ([]byte, error) {
	var _, errx = x_p.SetBytes(x)
	if errx != nil {
		return nil, errx
	}
	var _, erry = y_p.SetBytes(y)
	if erry != nil {
		return nil, erry
	}

	return x_p.Add(x_p, y_p.Negate(y_p)).BytesCompressed(), nil
}

func (p256 *P256) CofactorMultiply(x []byte) ([]byte, error) {
	var _, errx = x_p.SetBytes(x)
	if errx != nil {
		return nil, errx
	}

	var _, errm = x_p.ScalarMult(x_p, cofactor[:])
	if errm != nil {
		return nil, errm
	}
	return x_p.BytesCompressed(), nil
}

func (p256 *P256) ScalarMultiply(x []byte, k *big.Int) ([]byte, error) {
	var _, errx = x_p.SetBytes(x)
	if errx != nil {
		return nil, errx
	}

	var k_byte, errk1 = util.I2SOP(k, 32, "")
	if errk1 != nil {
		return nil, errk1
	}

	var _, errm = x_p.ScalarMult(x_p, k_byte)
	if errm != nil {
		return nil, errm
	}
	return x_p.BytesCompressed(), nil
}

func (p256 *P256) ScalarBaseMultiply(k *big.Int) ([]byte, error) {
	var k_byte, errk1 = util.I2SOP(k, 32, "")
	if errk1 != nil {
		return nil, errk1
	}
	x_p.SetGenerator()

	var _, errm = x_p.ScalarMult(x_p, k_byte)
	if errm != nil {
		return nil, errm
	}
	return x_p.BytesCompressed(), nil
}

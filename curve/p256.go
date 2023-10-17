package curve

import (
	"encoding/hex"
	"errors"
	"math/big"

	"crypto/elliptic"
	"crypto/sha256"

	"example.com/temp/util"
	"filippo.io/nistec"
)

type P256 Curve

func NewP256() P256 {
	// p: 2^256 - 2^224 + 2^192 + 2^96 - 1
	var prime_ed, t = big.NewInt(2), big.NewInt(2)
	prime_ed.Exp(prime_ed, big.NewInt(256), nil)
	t.Exp(t, big.NewInt(224), nil)
	prime_ed.Sub(prime_ed, t)
	t.Exp(big.NewInt(2), big.NewInt(192), nil)
	prime_ed.Add(prime_ed, t)
	t.Exp(big.NewInt(2), big.NewInt(96), nil)
	prime_ed.Add(prime_ed, t)
	prime_ed.Sub(prime_ed, big.NewInt(1))

	z_maj.Mod(z_maj, prime_ed)
	a_maj.Mod(a_maj, prime_ed)

	var b_maj_os, _ = hex.DecodeString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	b_maj = util.OS2IP(b_maj_os, "")

	return P256{
		prime: prime_ed,
		order: prime_ed,
		l_maj: big.NewInt(48),
		m:     big.NewInt(1),
		hash:  sha256.New(),
	}
}

var a_maj = big.NewInt(-3)
var b_maj = big.NewInt(1)
var z_maj = big.NewInt(-10)

// ----------- E2C Interface -----------
// F.2.1.2.  Optimized sqrt_ratio for q = 3 mod 4
func (p256 P256) sqrt_ratio(u, v *big.Int) (bool, *big.Int) {
	var c1, c2, tv1, tv2, tv3, y1, y2 big.Int

	//c1 = (q - 3) / 4
	c1.Sub(p256.prime, big.NewInt(3))
	c1.Div(&c1, big.NewInt(4))

	//c2 = sqrt(-Z)
	c2.Neg(z_maj)
	c2.Mod(&c2, p256.prime)
	c2 = *util.Sqrt(&c2, p256.prime)

	//tv1 = v^2
	tv1.Exp(v, big.NewInt(2), p256.prime)

	//tv2 = u * v
	tv2.Mul(u, v)
	tv2.Mod(&tv2, p256.prime)

	//tv1 = tv1 * tv2
	tv1.Mul(&tv1, &tv2)
	tv1.Mod(&tv1, p256.prime)

	//y1 = tv1^c1
	y1.Exp(&tv1, &c1, p256.prime)

	//y1 = y1 * tv2
	y1.Mul(&y1, &tv2)
	y1.Mod(&y1, p256.prime)

	//y2 = y1 * c2
	y2.Mul(&y1, &c2)
	y2.Mod(&y2, p256.prime)

	//tv3 = y1^2
	tv3.Exp(&y1, big.NewInt(2), p256.prime)

	//tv3 = tv3 * v
	tv3.Mul(&tv3, v)
	tv3.Mod(&tv3, p256.prime)

	//isQR = tv3 == u
	//y = CMOV(y2, y1, isQR)
	if tv3.Cmp(u) == 0 {
		return true, &y1
	}
	return false, &y2
}

// see Section F.2.  Simplified SWU Method of rfc 9380
func (p256 P256) SSWU(u *big.Int) (*big.Int, *big.Int) {
	var tv1, tv2, tv3, tv4, tv5, tv6 big.Int

	//tv1 = u^2
	tv1.Exp(u, big.NewInt(2), p256.prime)

	//tv1 = Z * tv1
	tv1.Mul(z_maj, &tv1)
	tv1.Mod(&tv1, p256.prime)

	//tv2 = tv1^2
	tv2.Exp(&tv1, big.NewInt(2), p256.prime)

	//tv2 = tv2 + tv1
	tv2.Add(&tv2, &tv1)
	tv2.Mod(&tv2, p256.prime)

	//tv3 = tv2 + 1
	tv3.Add(&tv2, big.NewInt(1))
	tv3.Mod(&tv3, p256.prime)

	//tv3 = B * tv3
	tv3.Mul(b_maj, &tv3)
	tv3.Mod(&tv3, p256.prime)

	//tv4 = CMOV(Z, -tv2, tv2 != 0)
	if tv2.Cmp(big.NewInt(0)) == 0 {
		tv4.Set(z_maj)
	} else {
		tv4.Neg(&tv2)
	}
	tv4.Mod(&tv4, p256.prime)

	//tv4 = A * tv4
	tv4.Mul(a_maj, &tv4)
	tv4.Mod(&tv4, p256.prime)

	//tv2 = tv3^2
	tv2.Exp(&tv3, big.NewInt(2), p256.prime)

	//tv6 = tv4^2
	tv6.Exp(&tv4, big.NewInt(2), p256.prime)

	//tv5 = A * tv6
	tv5.Mul(a_maj, &tv6)
	tv5.Mod(&tv5, p256.prime)

	//tv2 = tv2 + tv5
	tv2.Add(&tv2, &tv5)
	tv2.Mod(&tv2, p256.prime)

	//tv2 = tv2 * tv3
	tv2.Mul(&tv2, &tv3)
	tv2.Mod(&tv2, p256.prime)

	//tv6 = tv6 * tv4
	tv6.Mul(&tv6, &tv4)
	tv6.Mod(&tv6, p256.prime)

	//tv5 = B * tv6
	tv5.Mul(b_maj, &tv6)
	tv5.Mod(&tv5, p256.prime)

	//tv2 = tv2 + tv5
	tv2.Add(&tv2, &tv5)
	tv2.Mod(&tv2, p256.prime)

	var x, y big.Int
	//x = tv1 * tv3
	x.Mul(&tv1, &tv3)
	x.Mod(&x, p256.prime)

	//(is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	var is_gx1_square, y1 = p256.sqrt_ratio(&tv2, &tv6)

	//y = tv1 * u
	y.Mul(&tv1, u)
	y.Mod(&y, p256.prime)

	//y = y * y1
	y.Mul(&y, y1)
	y.Mod(&y, p256.prime)

	//x = CMOV(x, tv3, is_gx1_square)
	//y = CMOV(y, y1, is_gx1_square)
	if is_gx1_square {
		x.Set(&tv3)
		y.Set(y1)
	}

	//e1 = sgn0(u) == sgn0(y)
	//y = CMOV(-y, y, e1)
	if util.Sgn0Meq1(u).Cmp(util.Sgn0Meq1(&y)) != 0 {
		y.Neg(&y)
		y.Mod(&y, p256.prime)
	}
	//x = x / tv4
	x.Mul(&x, util.Inv0(&tv4, p256.prime))
	x.Mod(&x, p256.prime)

	return &x, &y
}

// Implement SSWU Method (Simplified Shallue-van de Woestijne-Ulas Method)
func (p256 P256) Map2Curve(u []big.Int) ([]byte, error) {
	var u_0 *big.Int
	if len(u) == 1 {
		u_0 = &u[0]
	}
	var xt, yt = p256.SSWU(u_0)
	if !elliptic.P256().IsOnCurve(xt, yt) {
		return nil, errors.New("point not on curve")
	}
	var uell2 = elliptic.MarshalCompressed(elliptic.P256(), xt, yt)

	return uell2, nil
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
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
}
var x_p = nistec.NewP256Point()
var y_p = nistec.NewP256Point()

func (p256 P256) Add(x []byte, y []byte) ([]byte, error) {
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

func (p256 P256) Subtract(x []byte, y []byte) ([]byte, error) {
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

func (p256 P256) CofactorMultiply(x []byte) ([]byte, error) {
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

func (p256 P256) ScalarMultiply(x []byte, k *big.Int) ([]byte, error) {
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

func (p256 P256) ScalarBaseMultiply(k *big.Int) ([]byte, error) {
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

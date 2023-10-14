package curve

import (
	"crypto/sha512"
	"encoding/hex"
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
	var prime_ed = big.NewInt(2)
	prime_ed.Exp(prime_ed, big.NewInt(255), nil)
	prime_ed.Sub(prime_ed, big.NewInt(19))

	var order = big.NewInt(2)
	order.Exp(order, big.NewInt(252), nil)
	var t, _ = hex.DecodeString("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	order.Add(order, util.OS2IP(t, ""))
	return Ed25519{
		prime: prime_ed,
		order: order,
		l_maj: big.NewInt(48),
		m:     big.NewInt(1),
		hash:  sha512.New(),
	}
}

var j_maj = big.NewInt(486662)
var k_maj = big.NewInt(1)
var z_maj_ed = big.NewInt(2)

func (ed Ed25519) elligator2(u *big.Int) (*big.Int, *big.Int) {
	var c1 big.Int
	c1.Div(j_maj, k_maj)
	var minusc1 big.Int
	minusc1.Neg(&c1)
	minusc1.Mod(&minusc1, ed.prime)

	var c2 big.Int
	c2.Exp(k_maj, big.NewInt(2), nil)
	c2.Div(big.NewInt(1), &c2)

	var tv1 big.Int
	tv1.Exp(u, big.NewInt(2), ed.prime)
	tv1.Mul(z_maj_ed, &tv1)
	tv1.Mod(&tv1, ed.prime)
	var tvc big.Int
	tvc.Mod(big.NewInt(-1), ed.prime)
	if tv1.Cmp(&tvc) == 0 {
		tv1.SetInt64(0)
	}
	var x1 big.Int
	x1.Add(&tv1, big.NewInt(1))
	x1.Set(util.Inv0(&x1, ed.prime))
	x1.Mul(&minusc1, &x1)
	x1.Mod(&x1, ed.prime)

	var gx1 big.Int
	gx1.Add(&x1, &c1)
	gx1.Mod(&gx1, ed.prime)
	gx1.Mul(&gx1, &x1)
	gx1.Mod(&gx1, ed.prime)
	gx1.Add(&gx1, &c2)
	gx1.Mod(&gx1, ed.prime)
	gx1.Mul(&gx1, &x1)
	gx1.Mod(&gx1, ed.prime)

	var x2 big.Int
	x2.Neg(&x1)
	x2.Mod(&x2, ed.prime)
	x2.Sub(&x2, &c1)
	x2.Mod(&x2, ed.prime)

	var gx2 big.Int
	gx2.Mul(&gx1, &tv1)
	gx2.Mod(&gx2, ed.prime)

	var x, y big.Int
	if util.IsSquare(&gx1, ed.prime) {
		x.Set(&x1)
		y.Set(&gx1)
	} else {
		x.Set(&x2)
		y.Set(&gx2)
	}
	y.Set(util.Sqrt(&y, ed.prime))
	y.Mod(&y, ed.prime)

	if (util.Sgn0Meq1(&y).Cmp(big.NewInt(1)) == 0) != (util.IsSquare(&gx1, ed.prime)) {
		y.Neg(&y)
		y.Mod(&y, ed.prime)
	}
	var s, t big.Int
	s.Mul(&x, k_maj)
	s.Mod(&s, ed.prime)
	t.Mul(&y, k_maj)
	t.Mod(&t, ed.prime)

	return &s, &t

}

// (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
func (ed Ed25519) rational_map(s *big.Int, t *big.Int) (*big.Int, *big.Int) {
	var inv_t, s_t, s_1, v, w big.Int
	inv_t.Set(util.Inv0(t, ed.prime))
	s_t.Mul(s, &inv_t)
	s_t.Mod(&s_t, ed.prime)

	v.Mul(util.Sqrt(big.NewInt(-486664), ed.prime), &s_t)
	v.Mod(&v, ed.prime)

	w.Add(s, big.NewInt(-1))
	s_1.Add(s, big.NewInt(1))
	w.Mul(&w, util.Inv0(&s_1, ed.prime))
	w.Mod(&w, ed.prime)

	return &v, &w
}

func (ed Ed25519) encode(x, y *big.Int) ([]byte, error) {
	var s, err1 = util.I2SOP(y, 32, "little")
	if err1 != nil {
		return nil, err1
	}
	var xo, err2 = util.I2SOP(x, 32, "little")
	if err2 != nil {
		return nil, err2
	}
	s[31] |= byte(int(xo[0]&1) << 7)

	return s, nil
}

func (ed Ed25519) Map2Curve(u []big.Int) ([]byte, error) {
	var s1, t1 = ed.elligator2(&u[0])

	var v2, w2 = ed.rational_map(s1, t1)

	var point, err = ed.encode(v2, w2)

	if err != nil {
		return nil, err
	}
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

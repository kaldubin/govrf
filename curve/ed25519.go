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

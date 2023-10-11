package curve

import (
	"math/big"

	"example.com/temp/util"
	"filippo.io/edwards25519"
)

type Ed25519 struct {
}

func (ed *Ed25519) Add(x []byte, y []byte) ([]byte, error) {

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

func (ed *Ed25519) Subtract(x []byte, y []byte) ([]byte, error) {
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

func (ed *Ed25519) CofactorMultiply(x []byte) ([]byte, error) {
	var x_p, errx = edwards25519.NewIdentityPoint().SetBytes(x)
	if errx != nil {
		return nil, errx
	}

	return x_p.MultByCofactor(x_p).Bytes(), nil
}

func (ed *Ed25519) ScalarMultiply(x []byte, k *big.Int) ([]byte, error) {
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

func (ed *Ed25519) ScalarBaseMultiply(k *big.Int) ([]byte, error) {
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

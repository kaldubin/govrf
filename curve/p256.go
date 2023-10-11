package curve

import (
	"math/big"

	"example.com/temp/util"
	"filippo.io/nistec"
)

type P256 struct {
}

var cofactor = [32]byte{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
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

package curve

import (
	"crypto"
	"math/big"
)

//	type Curve struct {
//		Hash                                    crypto.Hash
//		prime, m, order, cofactor, l_maj, ptLen *big.Int
//	}
//
// This interface would be used to perform Field Element arithmetic
// regardless of the type of Field Element as long as the type's
// function are defined in the same package
type CurveFunction interface {
	Add([]byte, []byte) ([]byte, error)
	Subtract([]byte, []byte) ([]byte, error)
	CofactorMultiply([]byte) ([]byte, error)
	ScalarMultiply([]byte, *big.Int) ([]byte, error)
	ScalarBaseMultiply(*big.Int) ([]byte, error)
}

type CurveParam struct {
	prime, order, l_maj, m *big.Int
	Hash                   crypto.Hash
}

func (c CurveParam) Map2Curve(u int) []byte {
	panic(1)
}

func (c CurveParam) Add([]byte, []byte) ([]byte, error) {
	panic(1)
}

func (c CurveParam) Subtract(x []byte, y []byte) ([]byte, error) {
	panic(1)
}

func (c CurveParam) CofactorMultiply(x []byte) ([]byte, error) {
	panic(1)
}

func (c CurveParam) ScalarMultiply(x []byte, k *big.Int) ([]byte, error) {
	panic(1)
}

func (c CurveParam) ScalarBaseMultiply(k *big.Int) ([]byte, error) {
	panic(1)
}

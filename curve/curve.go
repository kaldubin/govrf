package curve

import (
	"crypto"
	"math/big"
)

type Curve struct {
	Hash                                    crypto.Hash
	prime, m, order, cofactor, l_maj, ptLen *big.Int
}

// This interface would be used to perform Field Element arithmetic
// regardless of the type of Field Element as long as the type's
// function are defined in the same package
type CurveFunction interface {
	Add([]byte, []byte) []byte
	Subtract([]byte, []byte) []byte
	CofactorMultiply([]byte) []byte
	ScalarMultiply([]byte, *big.Int) []byte
	ScalarBaseMultiply(*big.Int) []byte
}

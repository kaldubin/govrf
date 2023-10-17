package curve

import (
	"hash"
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
type HashParam interface {
	Hash([]byte) []byte
	GetHashBlockSize() *big.Int
	GetHashSize() *big.Int
}

type CurveParam interface {
	HashParam
	GetOrder() *big.Int
	GetPrime() *big.Int
	GetM() *big.Int
	GetL() *big.Int
}

type CurveFunction interface {
	Add([]byte, []byte) ([]byte, error)
	Subtract([]byte, []byte) ([]byte, error)
	CofactorMultiply([]byte) ([]byte, error)
	ScalarMultiply([]byte, *big.Int) ([]byte, error)
	ScalarBaseMultiply(*big.Int) ([]byte, error)
}

type Curve struct {
	prime, order, l_maj, m *big.Int
	hash                   hash.Hash
}

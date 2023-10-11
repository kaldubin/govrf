package curve

import (
	"crypto"
	"math/big"
)

type Equation struct {
}

type Curve struct {
	Hash                                    crypto.Hash
	prime, m, order, cofactor, l_maj, ptLen int
}

// base_point                              [2]int
// equation                                Equation

type CurveFactory interface {
	Point2String([2]int) []byte
	String2Point([]byte) [2]int
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

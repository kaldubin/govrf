package curve

import (
	"crypto"
	"filippo.io/edwards25519" // imported as a replacement of crypto/internal are not meant to be imported
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
	Add()
	Mul()
}

type Ed25519Curve struct{}

// Something like that so that we can keep the code in e2c.go as close to python as possible
func (c *Ed25519Curve) Add(a []uint, b []uint) []uint {
	var c = edwards25519.NewGeneratorPoint().Add(a, b)
	return c[]
}

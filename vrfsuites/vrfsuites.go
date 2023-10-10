package vrfsuites

import (
	"errors"
)

var (
	ErrVerify = errors.New("error, the random number's verification went wrong")
)

// Base Interface for Verifiable Random Function
type VRFSuite interface {
	Prove(sk, alpha []byte) ([]byte, error)
	Proof2Hash(pi []byte) ([]byte, error)
	Verify(pk, alpha []byte, pi []byte) ([]byte, error)
}

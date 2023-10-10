package rsa

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math"
	"math/big"

	"example.com/temp/util"
)

var (
	ErrMoutofrange = errors.New("RSASP1 error : m is out of range")
	ErrSoutofrange = errors.New("RSAVP1 error : s is out of range")
	ErrMasklen     = errors.New("MGF1 error : maskLen is too long")
)

type RSA struct {
	Hash hash.Hash
}

func New(hash string) RSA {
	return RSA{Hash: sha256.New()}
}

// RSASP1: RSA signature primitive as defined in section 5.2.1 of RFC8017
// K an RSA private key in the form (n, d)
// m the message representative, an integer
func (cs *RSA) RSASP1(K [2]big.Int, m *big.Int) (*big.Int, error) {

	var nminus1 big.Int
	if m.Cmp(nminus1.Add(big.NewInt(-1), &K[0])) > 0 {
		return nil, ErrMoutofrange
	}

	var s big.Int
	s.Exp(m, &K[1], &K[0])
	// var s = uint64(math.Pow(float64(m), float64(K[1]))) % K[0]

	return &s, nil
}

// RSAVP1: RSA verification primitive as defined in section 5.2.2 of RFC8017
// pk a RSA public key in the form (n, e)
// s the signature representation, an integer
func (cs *RSA) RSAVP1(pk [2]big.Int, s *big.Int) (*big.Int, error) {

	var nminus1 big.Int
	if s.Cmp(nminus1.Add(big.NewInt(-1), &pk[0])) > 0 {
		return nil, ErrSoutofrange
	}

	var m big.Int
	m.Exp(s, &pk[1], &pk[0])

	return &m, nil
}

// MGF1: Mask generation, based on the hash function, as defined in Appendix B.2.1 of RFC8017
// mgfSeed the seed from which mask is generated, an octet string
// maskLen intended length in octets of the mask at most 2^32
func (cs *RSA) MGF1(mgfSeed []byte, maskLen uint64) ([]byte, error) {

	var hLen = uint64(cs.Hash.Size())

	var T []byte
	// var out []byte
	cs.Hash.Reset()

	for counter := big.NewInt(0); counter.Cmp(big.NewInt(int64(math.Ceil(float64(maskLen)/float64(hLen))))) < 0; counter.Add(big.NewInt(1), counter) {
		var C, err1 = util.I2SOP(counter, 4, "")
		fmt.Println(C)
		if err1 != nil {
			return nil, err1
		}

		cs.Hash.Write(mgfSeed)
		cs.Hash.Write(C[0:4])
		T = cs.Hash.Sum(T)
		cs.Hash.Reset()
	}

	return T[:maskLen], nil
}

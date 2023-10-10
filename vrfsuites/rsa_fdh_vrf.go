package vrfsuites

import (
	"math/big"

	"example.com/temp/rsa"
	"example.com/temp/util"
)

// ---------------------------------- RSA VRF CYPHER SUITES ----------------------------------
// public key = pk = (n, e)
// private key = sk = K = (n, d)
// k length in octets of the RSA modulus n (k is less than 2^32) --> var k = math.bits.Len(n)
// RSASP1: RSA signature primitive as defined in section 5.2.1 of RFC8017
// RSAVP1: RSA verification primitive as defined in section 5.2.2 of RFC8017
// MGF1: Mask generation, based on the hash function, as defined in Appendix B.2.1 of RFC8017
//
// ### RSA_FDH_SHA256
// suite_string = 0x01
// hash = sha256, hlen = 32
// MGF_salt = util.Concat(I2OSP(k, 4), I2SOP(n, k))
//
// ### RSA_FDH_SHA384
// suite_string = 0x02
// hash = sha384, hlen = 48
// MGF_salt = util.Concat(I2OSP(k, 4), I2SOP(n, k))
//
// ### RSA_FDH_SHA512
// suite_string = 0x03
// hash = sha512, hlen = 64
// MGF_salt = util.Concat(I2OSP(k, 4), I2SOP(n, k))
//
// -------------------------------------------------------------------------------------------

type RSA_FDH_VRF struct {
	RSA                    rsa.RSA
	MGF_salt, Suite_string []byte
}

func (cs *RSA_FDH_VRF) Prove(sk [2]big.Int, alpha []byte) ([]byte, error) {

	var k = len(sk[0].Bytes())
	var mgf_domain_separator = []byte{0x01}

	var seed = util.Concat([][]byte{cs.Suite_string, mgf_domain_separator, cs.MGF_salt, alpha})
	var EM, err1 = cs.RSA.MGF1(
		seed,
		uint64(k-1),
	)
	if err1 != nil {
		return nil, err1
	}

	var m = util.OS2IP(EM, "")

	var s, err2 = cs.RSA.RSASP1(sk, m)
	if err2 != nil {
		return nil, err2
	}

	var pi_string, err3 = util.I2SOP(s, k, "")
	if err3 != nil {
		return nil, err3
	}

	return pi_string, nil
}

func (cs *RSA_FDH_VRF) Proof2Hash(pi_string []byte) ([]byte, error) {

	var proof_to_hash_separator = []byte{0x02}

	var _, err1 = cs.RSA.Hash.Write(util.Concat([][]byte{cs.Suite_string, proof_to_hash_separator, pi_string}))
	if err1 != nil {
		return nil, err1
	}

	var beta_string = cs.RSA.Hash.Sum([]byte{})
	cs.RSA.Hash.Reset()

	return beta_string, nil
}

func (cs *RSA_FDH_VRF) Verify(pk [2]big.Int, alpha []byte, pi_string []byte) ([]byte, error) {

	var s = util.OS2IP(pi_string, "")
	var k = len(pk[0].Bytes())

	// if RSAVP1 returns "signature representative out of range", output "INVALID" and stop
	var m, err1 = cs.RSA.RSAVP1(pk, s)
	if err1 != nil {
		return nil, err1
	}

	var mgf_domain_separator = []byte{0x01}

	var EMprime, err2 = cs.RSA.MGF1(
		util.Concat([][]byte{cs.Suite_string, mgf_domain_separator, cs.MGF_salt, alpha}),
		uint64(k-1),
	)
	if err2 != nil {
		return nil, err2
	}

	var m_prime = util.OS2IP(EMprime, "")

	if m.Cmp(m_prime) != 0 {
		return nil, ErrVerify
	}

	var beta_string, err3 = cs.Proof2Hash(pi_string)
	if err3 != nil {
		return nil, err3
	}

	return beta_string, nil
}

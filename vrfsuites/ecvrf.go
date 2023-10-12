package vrfsuites

// -------------------------- Elliptic Curve VRF CYPHER SUITES -------------------------------
// public key = pk
// private key = sk
// ECVRF_encode_to_curve as describe in section 5.4.1 with :
// - interpret_hash_value_as_a_point(s) describe in section 5.4.1.1 of RFC9381
// - encode_to_curve describe in section 5.4.1.2 of RFC9381
//
// ### CVRF-P256-SHA256-TAI
// suite_string = 0x01
// hash = sha256, hlen = 32
// fLen = qLen = 32
// cLen = 16
// cofactor = 1
// ptLen = 33
// ECVRF_encode_to_curve = interpret_hash_value_as_a_point(s) = string_to_point(0x02 || s)
//
// ### ECVRF-P256-SHA256-SSWU
// suite_string = 0x02
// hash = sha256, hlen = 32
// fLen = qLen = 32
// cLen = 16
// cofactor = 1
// ptLen = 33
// ECVRF_encode_to_curve with h2c_suite_ID_string = P256_XMD:SHA-256_SSWU_NU (suite defined in section 8.2 of RFC9830)
//
// ### ECVRF-EDWARDS25519-SHA512-TAI
// suite_string = 0x03
// hash = sha512, hlen = 64
// fLen = qLen = 32
// cLen = 16
// cofactor = 8
// ptLen = 32
// ECVRF_encode_to_curve = interpret_hash_value_as_a_point(s) = string_to_point(s[0]...s[31])
//
// ### ECVRF-EDWARDS25519-SHA512-ELL2
// suite_string = 0x04
// hash = sha512, hlen = 64
// fLen = qLen = 32
// cLen = 16
// cofactor = 8
// ptLen = 32
// ECVRF_encode_to_curve with h2c_suite_ID_string = edwards25519_XMD:SHA-512_ELL2_NU (suite defined in section 8.5 of RFC9830)
//
// -------------------------------------------------------------------------------------------

// type ECVRF struct {
// 	suite_string                      []byte
// 	fLen, qLen, cLen, ptLen, int
// 	hash                              crypto.Hash
// }

// func (cs *ECVRF) Prove(sk, alpha []byte) ([]byte, error) {

// 	var pk = sk.GetPublicKey()

// 	var H = cs.ECVRF_encode_to_curve(pk, alpha)

// 	var h = cs.Point2String(H)

// 	var Gamma = H.ScalarMultiply(sk)

// 	var k = cs.ECVRF_nonce_generation(sk, h)

// 	var c = cs.ECVRF_challenge_generation(pk, H, Gamma, cs.BasePoint.ScalarMultiply(k), H.ScalarMultiply(k))

// 	var s = (k + c*sk) % cs.q

// 	var c_byte, err1 = util.I2SOP(c, uint64(cs.cLen), "")
// 	if err1 != nil {
// 		return nil, err1
// 	}
// 	var s_byte, err2 = util.I2SOP(s, uint64(cs.qLen), "")
// 	if err2 != nil {
// 		return nil, err2
// 	}
// 	var pi_string = util.Concat([][]byte{
// 		cs.Point2String(Gamma), c_byte, s_byte,
// 	})

// 	return pi_string, nil
// }

// func (cs *ECVRF) Proof2Hash(pi []byte) ([]byte, error) {

// 	var D, err1 = cs.ECVRF_decode_proof(pi)
// 	if err1 != nil {
// 		return nil, err1
// 	}

// 	var Gamma, c, s = D

// 	var proof_to_hash_domain_separator_front = 0x03

// 	var proof_to_hash_domain_separator_back = 0x00

// 	var hash = cs.hash.New()
// 	var _, err2 = hash.Write(util.Concat([][]byte{
// 		cs.suite_string, proof_to_hash_domain_separator_front, cs.Point2String(Gamma.ScalarMultiply(cs.cofactor)), proof_to_hash_domain_separator_back,
// 	}))
// 	if err2 != nil {
// 		return nil, err2
// 	}
// 	var beta_string = hash.Sum([]byte{})

// 	return beta_string, nil
// }

// func (cs *ECVRF) Verify(pk []byte, alpha []byte, pi_string []byte) ([]byte, error) {

// 	var Y, err1 = cs.String2Point(pk)
// 	if err1 != nil {
// 		return nil, err1
// 	}

// 	var D, err2 = cs.ECVRF_decode_proof(pi_string)
// 	if err2 != nil {
// 		return nil, err2
// 	}

// 	var Gamma, c, s = D

// 	var H = cs.ECVRF_encode_to_curve(pk, alpha)

// 	var U = cs.BasePoint.ScalarMultiply(s) - Y.ScalarMultiply(c)

// 	var V = H.ScalarMultiply(s) - Gamma.ScalarMultiply(c)

// 	var c_prime = cs.ECVRF_challenge_generation(Y, H, Gamma, U, V)

// 	if c != c_prime {
// 		return nil, ErrVerify
// 	}

// 	var beta_string, err3 = cs.Proof2Hash(pi_string)
// 	if err3 != nil {
// 		return nil, err3
// 	}

// 	return beta_string, nil
// }

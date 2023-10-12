package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"example.com/temp/curve"
	"example.com/temp/rsa"
	"example.com/temp/util"
	"example.com/temp/vrfsuites"
	"filippo.io/edwards25519"
)

func test_expandxmd(dont bool) {
	if dont {
		return
	}
	var ed = curve.NewEd25519()

	var dst_maj = []byte("QUUX-V01-CS02-with-expander-SHA512-256")
	var len_byte = big.NewInt(0x20)

	var uniform_bytes, err = curve.ExpandMsgXmd([]byte("abc"), len_byte, dst_maj, ed)
	fmt.Println(err)
	fmt.Println(hex.EncodeToString(uniform_bytes))
}

// func incCounter(c *[4]byte) {
// 	if c[3]++; c[3] != 0 {
// 		return
// 	}
// 	if c[2]++; c[2] != 0 {
// 		return
// 	}
// 	if c[1]++; c[1] != 0 {
// 		return
// 	}
// 	c[0]++
// }

// func mgf1XOR(out []byte, seed []byte) {
// 	var sha = sha256.New()
// 	var counter [4]byte
// 	var digest []byte

// 	done := 0

// 	for done < len(out) {
// 		sha.Write(seed)
// 		sha.Write(counter[0:4])
// 		digest = sha.Sum(digest[:0])
// 		sha.Reset()

// 		for i := 0; i < len(digest) && done < len(out); i++ {
// 			out[done] = digest[i]
// 			done++
// 		}
// 		incCounter(&counter)
// 	}
// 	// fmt.Println(hex.EncodeToString(digest))
// }

func test_filipio(dont bool) {
	if dont {
		return
	}
	var k = big.NewInt(1)
	fmt.Println(k.Bytes())
	fmt.Println(len(k.Bytes()))
	var k_byte, _ = util.I2SOP(k, 32, "little")
	fmt.Println(k_byte)
	var edk, _ = edwards25519.NewScalar().SetCanonicalBytes(k_byte)
	fmt.Println(edk)

	var b = edwards25519.NewGeneratorPoint()
	var pt = edwards25519.NewGeneratorPoint()
	fmt.Println(b.Bytes())
	fmt.Println(pt.Bytes())
	fmt.Println(pt.Equal(b))
	pt.ScalarBaseMult(edk)
	fmt.Println(pt.Bytes())
	fmt.Println(pt.Equal(b))
}

func test_RSASP1(dont bool) {
	if dont {
		return
	}
	var EM, _ = hex.DecodeString("092ea69ca4f5630d4bd1012805ad23528a5f44c040829b4a0208491913ee39711889bce5347765072efb0b7f8ad9798c830085d9babe10c29f1a649dbb9a64c93a8cdaa325d37814faa15a1071ba81c39275f3cd66ce70fd21ee3acc7ac127c5de8f2a816b05aff19e4e63451cfe51fef059b2547302387449b4df1ab8eaa5bfc84dbbc5edf3b07eb8fe3fe2a93858bd0d55d6f0686f2eb449ed4c609b3083de04b49d409a425509d89d282de806a6ce66892edc30337f780b15c7695b26383516f1fc18f7eab52557c654467600e2e272ef41e7e4a060b42f7533bae603a7fa50f497a64a1508b93826d99643a2001d1c958a7a06da0370668634d678a5de")
	var n_byte, _ = hex.DecodeString("ddaba77202bafb796b85bcec98958aa58ae2d117cbc66a6e75c4c2af983985a3064eaef93e2b03393256d94d75d6a6656b2956524ed8711898a0c3abae84371da0283bc5f433fc384d810a3c118ed302c0b03da16bee70b80ba3480e7acc1eb358b3f20fbe90cc4c8a7e2ba9e28b2a3800a5efbaa3c264f79b231f7cdc9577818df1bac60ef7a3f78a44f046fd29b0689556da7a7f61eefe67427f3f691aee0a4b1efe2ee2e0e6091143ebb7d69254c9d8ab01ff5e0ad7329f566082f9251e64f436c547e68de75351ea3a09746ceb7efed2d234121088aaed01696583c172ec88bc173a0d4d8ec43f4dcc18ff8379317e83ef9685536283368c9c6deb783075")
	var d_byte, _ = hex.DecodeString("d5c5ceab929a841e2a654536de4788f7f0a2a086d44bbb245f8aab3df00db924e8d644c3b502820f4cce98adacf09e73bc0e9762b50ae2b697aaa24914fa08b51758f59c07cf827341bb2a0597e126f9c69db031d60692c9cadf62842444696f08223154a1b0be752a325725748644e6d12935b1c66f983379773bcc8c65d06262e93b5bb774dd2784265c23e9a7fc5e8871eb6bcc9968a6bc360a98874b623ec59f41af0a9ecec6af095cb7e5aca11472363950dcbbfcf678fe003358b4ff0060a391daa45a1bd81c166b6221fb07e4f5da75e27d8d5fdbbf87ecbd7f5a4d804597070faaed22f197511b218788816689375245ddf7fa12337f3e7e898fb9d9")

	var n = util.OS2IP(n_byte, "")
	fmt.Println(n)
	var d = util.OS2IP(d_byte, "")

	var m = util.OS2IP(EM, "")
	fmt.Println(m)

	var rsa_sha256 = rsa.New("")

	var s, _ = rsa_sha256.RSASP1([2]big.Int{*n, *d}, m)
	fmt.Println("n et s:")
	fmt.Println(n)
	fmt.Println(s)
	fmt.Println(m)
	fmt.Println("")

	var pi_string, _ = util.I2SOP(s, 256, "")
	fmt.Println(pi_string)
	fmt.Println(hex.EncodeToString(pi_string))
}

func test_RSA_Verify(dont bool) {
	if dont {
		return
	}
	var n_byte, _ = hex.DecodeString("ddaba77202bafb796b85bcec98958aa58ae2d117cbc66a6e75c4c2af983985a3064eaef93e2b03393256d94d75d6a6656b2956524ed8711898a0c3abae84371da0283bc5f433fc384d810a3c118ed302c0b03da16bee70b80ba3480e7acc1eb358b3f20fbe90cc4c8a7e2ba9e28b2a3800a5efbaa3c264f79b231f7cdc9577818df1bac60ef7a3f78a44f046fd29b0689556da7a7f61eefe67427f3f691aee0a4b1efe2ee2e0e6091143ebb7d69254c9d8ab01ff5e0ad7329f566082f9251e64f436c547e68de75351ea3a09746ceb7efed2d234121088aaed01696583c172ec88bc173a0d4d8ec43f4dcc18ff8379317e83ef9685536283368c9c6deb783075")
	var e_byte, _ = hex.DecodeString("010001")
	var pi, _ = hex.DecodeString("14234ff8a9487e1b36a23086e258135b8a8a7ff2e23f19c0dfeca0c0a943f119ebd336fdc292ef67b56e32ba06f9941893754a8b97c82f68974b2b34c17f6d43bfd55eb110cd7ea3452d59a24e4ddb8d4cdf040c814e22e3537ca09c2e2dc5dd8ea281e6492ad335378f9f437eed30c51eeeee66ef14efb4000c75c802e9c5a6bb8039c0258d4347981159d0ef6990b5e9c8ac2fb03915d7ff1ffa0626e2e11714a63342e59124c1fcea8e2816c1d9a7751feaaa66cf6c82cd3c58ffde66460d98246ab358cc33baefae4dfb0d191e9b6d6c0e3f92c35200408925dc8bef39b78d1259f8163a5003a693555f05290ef2e68345f27c6e2a8847c5c919d92e7505")
	var alpha, _ = hex.DecodeString("")

	var n = util.OS2IP(n_byte, "")
	var e = util.OS2IP(e_byte, "")

	var front, err1 = util.I2SOP(big.NewInt(int64(len(n_byte))), 4, "")
	fmt.Println(front)
	if err1 != nil {
		fmt.Println("Error 1")
		fmt.Println(err1)
		return
	}

	var back, err2 = util.I2SOP(n, len(n_byte), "")
	if err2 != nil {
		fmt.Println("Error 2")
		fmt.Println(err2)
		return
	}
	var rsa_sha256 = rsa.New("")
	var rsa_vrf = vrfsuites.RSA_FDH_VRF{
		RSA:          rsa_sha256,
		MGF_salt:     util.Concat([][]byte{front, back}),
		Suite_string: []byte{0x01},
	}

	var beta, err = rsa_vrf.Verify([2]big.Int{*n, *e}, alpha, pi)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("beta string:")
	fmt.Println(hex.EncodeToString(beta))

}

func test_RSA_P2H(dont bool) {
	if dont {
		return
	}
	var n_byte, _ = hex.DecodeString("ddaba77202bafb796b85bcec98958aa58ae2d117cbc66a6e75c4c2af983985a3064eaef93e2b03393256d94d75d6a6656b2956524ed8711898a0c3abae84371da0283bc5f433fc384d810a3c118ed302c0b03da16bee70b80ba3480e7acc1eb358b3f20fbe90cc4c8a7e2ba9e28b2a3800a5efbaa3c264f79b231f7cdc9577818df1bac60ef7a3f78a44f046fd29b0689556da7a7f61eefe67427f3f691aee0a4b1efe2ee2e0e6091143ebb7d69254c9d8ab01ff5e0ad7329f566082f9251e64f436c547e68de75351ea3a09746ceb7efed2d234121088aaed01696583c172ec88bc173a0d4d8ec43f4dcc18ff8379317e83ef9685536283368c9c6deb783075")
	var pi, _ = hex.DecodeString("14234ff8a9487e1b36a23086e258135b8a8a7ff2e23f19c0dfeca0c0a943f119ebd336fdc292ef67b56e32ba06f9941893754a8b97c82f68974b2b34c17f6d43bfd55eb110cd7ea3452d59a24e4ddb8d4cdf040c814e22e3537ca09c2e2dc5dd8ea281e6492ad335378f9f437eed30c51eeeee66ef14efb4000c75c802e9c5a6bb8039c0258d4347981159d0ef6990b5e9c8ac2fb03915d7ff1ffa0626e2e11714a63342e59124c1fcea8e2816c1d9a7751feaaa66cf6c82cd3c58ffde66460d98246ab358cc33baefae4dfb0d191e9b6d6c0e3f92c35200408925dc8bef39b78d1259f8163a5003a693555f05290ef2e68345f27c6e2a8847c5c919d92e7505")

	var n = util.OS2IP(n_byte, "")

	var front, err1 = util.I2SOP(big.NewInt(int64(len(n_byte))), 4, "")
	fmt.Println(front)
	if err1 != nil {
		fmt.Println("Error 1")
		fmt.Println(err1)
		return
	}

	var back, err2 = util.I2SOP(n, len(n_byte), "")
	if err2 != nil {
		fmt.Println("Error 2")
		fmt.Println(err2)
		return
	}
	var rsa_sha256 = rsa.New("")
	var rsa_vrf = vrfsuites.RSA_FDH_VRF{
		RSA:          rsa_sha256,
		MGF_salt:     util.Concat([][]byte{front, back}),
		Suite_string: []byte{0x01},
	}

	var beta, err = rsa_vrf.Proof2Hash(pi)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("beta string:")
	fmt.Println(hex.EncodeToString(beta))
}

func test_RSA_Prove(dont bool) {
	if dont {
		return
	}
	var p_byte, _ = hex.DecodeString("efb52a568fa3038fffb853e2183791c6bc81ceee86d20e8f9b6401dc79a8f1f6248d3a25fdb3f99245fce41667da038f59745b87cc1aed8b4a9c1d74e7d5c16cf7343f2b12f1b5055337369bf018fa07adc0d16f2164a516e80d2b4734f0c6563d6ee6d4a9e1a54e300cfe9ee679afc3d14a152dfb49b6cfb208bbf921f764af")
	var q_byte, _ = hex.DecodeString("ecbca5ee88bbc635d8263aaba84f6502fdb2b4998a40f7c149133d840b6b1bd9a972fe2a981c770272b78fda213f76a062dd865dd116d4c8980975ee9347fe0f500567e51d78dbee4a34e626051cf018d7feb72f19189525d4f70b6467d0cef514633ab08a9e7a9ec632064b7b5e3e82128fe563757a614092fc5cf624d10e1b")
	var n_byte, _ = hex.DecodeString("ddaba77202bafb796b85bcec98958aa58ae2d117cbc66a6e75c4c2af983985a3064eaef93e2b03393256d94d75d6a6656b2956524ed8711898a0c3abae84371da0283bc5f433fc384d810a3c118ed302c0b03da16bee70b80ba3480e7acc1eb358b3f20fbe90cc4c8a7e2ba9e28b2a3800a5efbaa3c264f79b231f7cdc9577818df1bac60ef7a3f78a44f046fd29b0689556da7a7f61eefe67427f3f691aee0a4b1efe2ee2e0e6091143ebb7d69254c9d8ab01ff5e0ad7329f566082f9251e64f436c547e68de75351ea3a09746ceb7efed2d234121088aaed01696583c172ec88bc173a0d4d8ec43f4dcc18ff8379317e83ef9685536283368c9c6deb783075")
	// var e_byte, _ = hex.DecodeString("010001")
	var d_byte, _ = hex.DecodeString("d5c5ceab929a841e2a654536de4788f7f0a2a086d44bbb245f8aab3df00db924e8d644c3b502820f4cce98adacf09e73bc0e9762b50ae2b697aaa24914fa08b51758f59c07cf827341bb2a0597e126f9c69db031d60692c9cadf62842444696f08223154a1b0be752a325725748644e6d12935b1c66f983379773bcc8c65d06262e93b5bb774dd2784265c23e9a7fc5e8871eb6bcc9968a6bc360a98874b623ec59f41af0a9ecec6af095cb7e5aca11472363950dcbbfcf678fe003358b4ff0060a391daa45a1bd81c166b6221fb07e4f5da75e27d8d5fdbbf87ecbd7f5a4d804597070faaed22f197511b218788816689375245ddf7fa12337f3e7e898fb9d9")

	var p = util.OS2IP(p_byte, "")
	var q = util.OS2IP(q_byte, "")
	fmt.Println(p)
	fmt.Println(q)

	var n = util.OS2IP(n_byte, "")
	// var e = util.OS2IP(e_byte, "")
	var d = util.OS2IP(d_byte, "")

	fmt.Println("Keys initialized !")
	var rsa_sha256 = rsa.New("")
	fmt.Println(len(n_byte))
	// fmt.Println(bits.Len64(n) * 4)

	var front, err1 = util.I2SOP(big.NewInt(int64(len(n_byte))), 4, "")
	fmt.Println(front)
	if err1 != nil {
		fmt.Println("Error 1")
		fmt.Println(err1)
		return
	}

	var back, err2 = util.I2SOP(n, len(n_byte), "")
	if err2 != nil {
		fmt.Println("Error 2")
		fmt.Println(err2)
		return
	}
	// fmt.Println(back)

	var rsa_vrf = vrfsuites.RSA_FDH_VRF{
		RSA:          rsa_sha256,
		MGF_salt:     util.Concat([][]byte{front, back}),
		Suite_string: []byte{0x01},
	}
	// p = 17272758497114784655
	// n = 15973044611513514873
	// m = 661649386982695693
	// s de RSASP1 = 9223372036854775808

	var alpha, _ = hex.DecodeString("")
	fmt.Println("alpha = ")
	fmt.Println(alpha)
	var EM, _ = hex.DecodeString("092ea69ca4f5630d4bd1012805ad23528a5f44c040829b4a0208491913ee39711889bce5347765072efb0b7f8ad9798c830085d9babe10c29f1a649dbb9a64c93a8cdaa325d37814faa15a1071ba81c39275f3cd66ce70fd21ee3acc7ac127c5de8f2a816b05aff19e4e63451cfe51fef059b2547302387449b4df1ab8eaa5bfc84dbbc5edf3b07eb8fe3fe2a93858bd0d55d6f0686f2eb449ed4c609b3083de04b49d409a425509d89d282de806a6ce66892edc30337f780b15c7695b26383516f1fc18f7eab52557c654467600e2e272ef41e7e4a060b42f7533bae603a7fa50f497a64a1508b93826d99643a2001d1c958a7a06da0370668634d678a5de")
	fmt.Println(len(EM))
	fmt.Println(util.OS2IP(EM, ""))
	var pi, _ = hex.DecodeString("14234ff8a9487e1b36a23086e258135b8a8a7ff2e23f19c0dfeca0c0a943f119ebd336fdc292ef67b56e32ba06f9941893754a8b97c82f68974b2b34c17f6d43bfd55eb110cd7ea3452d59a24e4ddb8d4cdf040c814e22e3537ca09c2e2dc5dd8ea281e6492ad335378f9f437eed30c51eeeee66ef14efb4000c75c802e9c5a6bb8039c0258d4347981159d0ef6990b5e9c8ac2fb03915d7ff1ffa0626e2e11714a63342e59124c1fcea8e2816c1d9a7751feaaa66cf6c82cd3c58ffde66460d98246ab358cc33baefae4dfb0d191e9b6d6c0e3f92c35200408925dc8bef39b78d1259f8163a5003a693555f05290ef2e68345f27c6e2a8847c5c919d92e7505")
	// var beta, _ = hex.DecodeString("79f0615d4677fb72571889453644013f1a31b08d222e3cee349d64ce1c41045a")

	var pi_string, err = rsa_vrf.Prove([2]big.Int{*n, *d}, alpha)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("\n----- PI_STRINGS -----")
		fmt.Println(hex.EncodeToString(pi_string))
		fmt.Println(hex.EncodeToString(pi))
	}

}

func main() {
	// var name string = "Math"
	// var name = "Math"

	// var name string
	// name = util.Encode()
	// fmt.Println(name)
	// var b []byte
	// b, _ = util.I2SOP(uint(111390), uint(16), "")

	// h := make([]byte, hex.EncodedLen(len(b)))
	// hex.Encode(h, b)
	// fmt.Printf("%s\n", h)

	// var h = sha512.New()
	// var _, _ = h.Write([]byte("hello world"))
	// var s1 = h.Sum([]byte{})
	// h.Reset()
	// var _, _ = h.Write([]byte("hello"))
	// var s2 = h.Sum([]byte{})

	// var b, err = util.I2SOP(uint64(38), uint64(1), "")
	// fmt.Println(err)
	// fmt.Println(b)
	// fmt.Println(hex.EncodeToString(b))

	// var c, err2 = util.I2SOP(0x20, uint64(2), "")
	// fmt.Println(err2)
	// fmt.Println(c)
	// fmt.Println(hex.EncodeToString(c))

	// fmt.Printf("%s\n%s\n", hex.EncodeToString(s1), hex.EncodeToString(s2))
	// fmt.Println(len(hex.EncodeToString(s1)))

	// test_expandxmd()
	// var i = 0x10
	// var i_byte = byte(i)
	// var j_byte = []byte{0x10}
	// fmt.Println(i)
	// fmt.Println(i_byte)
	// fmt.Println(j_byte)
	// fmt.Println(hex.EncodeToString([]byte{i_byte}))
	// fmt.Println(hex.EncodeToString(j_byte))

	var n_byte, _ = hex.DecodeString("ddaba77202bafb796b85bcec98958aa58ae2d117cbc66a6e75c4c2af983985a3064eaef93e2b03393256d94d75d6a6656b2956524ed8711898a0c3abae84371da0283bc5f433fc384d810a3c118ed302c0b03da16bee70b80ba3480e7acc1eb358b3f20fbe90cc4c8a7e2ba9e28b2a3800a5efbaa3c264f79b231f7cdc9577818df1bac60ef7a3f78a44f046fd29b0689556da7a7f61eefe67427f3f691aee0a4b1efe2ee2e0e6091143ebb7d69254c9d8ab01ff5e0ad7329f566082f9251e64f436c547e68de75351ea3a09746ceb7efed2d234121088aaed01696583c172ec88bc173a0d4d8ec43f4dcc18ff8379317e83ef9685536283368c9c6deb783075")

	var o1x = []byte{0x01}
	fmt.Println(o1x)
	fmt.Println(util.OS2IP(o1x, ""))

	var o1, _ = util.I2SOP(big.NewInt(1), 4, "little")
	fmt.Println(o1)
	var o256, _ = util.I2SOP(big.NewInt(256), 4, "little")
	fmt.Println(o256)
	var ibig big.Int
	ibig.SetBytes(n_byte)
	var obig, _ = util.I2SOP(&ibig, 255, "")
	// fmt.Println(hex.EncodeToString(obig))
	fmt.Println(util.OS2IP(o1, "little"))
	fmt.Println(util.OS2IP(o256, "little"))
	fmt.Println(util.OS2IP(obig, ""))

	// var out = make([]byte, 255)))

	fmt.Println("\n--- test Prove ---")
	test_RSA_Prove(true)

	fmt.Println("\n--- test RSASP1 ---")
	test_RSASP1(true)

	fmt.Println("\n--- test P2H ---")
	test_RSA_P2H(true)

	fmt.Println("\n--- test Verify ---")
	test_RSA_Verify(true)

	fmt.Println("\n--- test filipio ---")
	test_filipio(false)

	fmt.Println("\n--- test expandxmd ---")
	test_expandxmd(false)
}

// a49eea4c082081ca8e405f9e8c880f57de8f7e2a121eabd1e2815c233b22e4538cc20abb816f996a86b3c5a3bf047e8c4eab43a7158434aa5e57c28576f2e04cd3e83885d191ce6fddaff08622befb66ea1b2b2ed092a90551d873303717cb605491a9ba17d6692cc489c606ac2429b69ac02a5cf350514df6b7d0858bab80ec
// 9858e09cd83369e384a3313192d82063903224bdfa24881c70a2a0f1a37067f65dbe90cc14893e9cc37b3ee0087320980b35bcdb4f6547f8c76eff39bbfbca5866471f6ee5f983af38a05d203ee465d277409bbca6c989048a4123655ebc87769f33fba02fffe30e620762f0de256cb0bdf0a3e55b547110109296df1205d614a6bd529dc49ce5ca806e19e319b16d8f90115fb587680d4e63173de3a84420d4891ae2db6ffe08fcacfabdc58dbcdada0f649b9bebff905c131c873c6ab41b6e49db1cd2b14b742f64687ff1c4a0fbcc0d309618bad78bde88871bd4dec66857fad8d9304b8fa6d0135ef138ad7e47c353443676f2b749f16dd38d58115843

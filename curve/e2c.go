package curve

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"example.com/temp/util"
	"filippo.io/edwards25519"
)

var (
	ErrExpandmsgxmd = errors.New("expand message xmd error")
)

type E2C interface {
	CurveFunction
	CurveParam
	Map2Curve(u []big.Int) ([]byte, error)
}

func Encode(message []byte, dst []byte, curve E2C) ([]byte, error) {
	var u, err1 = Hash2Field(message, 1, dst, curve)
	if err1 != nil {
		return nil, err1
	}
	fmt.Println("u[0]")
	fmt.Println(hex.EncodeToString(u[0][0].Bytes()))

	var q_maj, err2 = curve.Map2Curve(u[0])
	if err2 != nil {
		return nil, err2
	}
	var q, _ = edwards25519.NewGeneratorPoint().SetBytes(q_maj)
	var Xq, Yq, Zq, _ = q.ExtendedCoordinates()
	Zq.Invert(Zq)
	var x_iq, y_iq = util.OS2IP(Xq.Multiply(Xq, Zq).Bytes(), "little"), util.OS2IP(Yq.Multiply(Yq, Zq).Bytes(), "little")
	fmt.Println("\nOutput Q x & y")
	fmt.Println(hex.EncodeToString(x_iq.Bytes()))
	fmt.Println(hex.EncodeToString(y_iq.Bytes()))

	var p_maj, err3 = ClearCofactor(q_maj, curve)
	if err3 != nil {
		return nil, err3
	}
	var p, _ = edwards25519.NewGeneratorPoint().SetBytes(p_maj)
	var X, Y, Z, _ = p.ExtendedCoordinates()
	Z.Invert(Z)
	var x_i, y_i = util.OS2IP(X.Multiply(X, Z).Bytes(), "little"), util.OS2IP(Y.Multiply(Y, Z).Bytes(), "little")
	fmt.Println("\nOutput P x & y")
	fmt.Println(hex.EncodeToString(x_i.Bytes()))
	fmt.Println(hex.EncodeToString(y_i.Bytes()))

	return p_maj, nil
}

func ExpandMsgXmd(message []byte, byteslen *big.Int, dst_maj []byte, ctx HashParam) ([]byte, error) {
	var ell = big.NewInt(0)
	ell.Div(byteslen, ctx.GetHashBlockSize())

	if ell.Cmp(big.NewInt(255)) > 0 || byteslen.Cmp(big.NewInt(65535)) > 0 || len(dst_maj) > 255 {
		return nil, ErrExpandmsgxmd
	}

	var varint, err1 = util.I2SOP(big.NewInt(int64(len(dst_maj))), 1, "")
	if err1 != nil {
		return nil, err1
	}

	var dst_prime = append(dst_maj, varint...)

	var z_pad, err2 = util.I2SOP(big.NewInt(0), int(ctx.GetHashBlockSize().Int64()), "")
	if err2 != nil {
		return nil, err2
	}

	var l_i_b, err3 = util.I2SOP(byteslen, 2, "")
	if err3 != nil {
		return nil, err3
	}

	var pad, _ = util.I2SOP(big.NewInt(0), 1, "")
	var msg_prime = util.Concat([][]byte{z_pad, message, l_i_b, pad, dst_prime})

	var b_0 = ctx.Hash(msg_prime)
	pad, _ = util.I2SOP(big.NewInt(1), 1, "")
	var b_1 = ctx.Hash(util.Concat([][]byte{b_0, pad, dst_prime}))

	var b_ell = [][]byte{b_1}
	for i := big.NewInt(2); i.Cmp(ell) <= 0; i.Add(i, big.NewInt(1)) {

		pad, _ = util.I2SOP(i, 1, "")
		var xor []byte
		copy(xor, b_0)
		for j := range b_0 {
			xor[j] = b_0[j] ^ b_ell[len(b_ell)-1][j]
		}

		var b_i = ctx.Hash(util.Concat([][]byte{xor, pad, dst_prime}))

		b_ell = append(b_ell, b_i)
	}

	var uniform_bytes = util.Concat(b_ell)

	return uniform_bytes[0:byteslen.Int64()], nil
}

func Hash2Field(message []byte, count int64, dst []byte, ctx CurveParam) ([][]big.Int, error) {

	var lenb = count * ctx.GetM().Int64() * ctx.GetL().Int64()

	var uniform_bytes, err1 = ExpandMsgXmd(message, big.NewInt(lenb), dst, ctx)

	if err1 != nil {
		return nil, err1
	}

	var u_count [][]big.Int
	for i := int64(0); i < count; i++ {
		var e_m = make([]big.Int, 0)

		for j := int64(0); j < ctx.GetM().Int64(); j++ {
			var elm_offset = ctx.GetL().Int64() * (j + i*ctx.GetM().Int64())
			var tv = util.Substr(uniform_bytes, uint(elm_offset), uint(ctx.GetL().Uint64()))
			var e_j = util.OS2IP(tv, "")
			e_j.Mod(e_j, ctx.GetPrime())

			e_m = append(e_m, *e_j)
		}

		u_count = append(u_count, e_m)

	}
	return u_count, nil

}

func ClearCofactor(q_maj []byte, ctx CurveFunction) ([]byte, error) {
	var ret, err = ctx.CofactorMultiply(q_maj)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

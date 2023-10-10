package curve

import (
	"errors"

	"example.com/temp/util"
)

var (
	ErrExpandmsgxmd = errors.New("expand message xmd error")
)

type E2C interface {
	Map2Curve(u int) any
	ExpandMsgXmd(message []byte, byteslen int, dst_maj []byte) ([]byte, error)
	Hash2Field(message []byte, count int, dst []byte) (uint64, error)
	ClearCofactor(q_maj any) any
	Encode(message []byte, dst []byte) (any, error)
}

func (c *Curve) Map2Curve(u int64) any {
	return nil
}

func (c *Curve) ExpandMsgXmd(message []byte, byteslen int, dst_maj []byte) ([]byte, error) {
	var ell int = byteslen / c.Hash.Size()

	if ell > 255 || byteslen > 65535 || len(dst_maj) > 255 {
		return nil, ErrExpandmsgxmd
	}

	var varint, err1 = util.I2SOP(uint64(len(dst_maj)), uint64(1), "")
	if err1 != nil {
		return nil, err1
	}

	var dst_prime = append(dst_maj, varint...)

	var z_pad, err2 = util.I2SOP(0, uint64(c.Hash.New().BlockSize()), "")
	if err2 != nil {
		return nil, err2
	}

	var l_i_b, err3 = util.I2SOP(uint64(byteslen), 2, "")
	if err3 != nil {
		return nil, err3
	}

	var pad, _ = util.I2SOP(0, 1, "")
	var msg_prime = util.Concat([][]byte{z_pad, message, l_i_b, pad, dst_prime})

	var h = c.Hash.New()

	h.Write(msg_prime)
	var b_0 = h.Sum([]byte{})
	h.Reset()

	pad, _ = util.I2SOP(1, 1, "")
	h.Write(util.Concat([][]byte{b_0, pad, dst_prime}))
	var b_1 = h.Sum([]byte{})

	var b_ell = [][]byte{b_1}
	for i := 2; i <= ell; i++ {
		h.Reset()

		pad, _ = util.I2SOP(uint64(i), 1, "")
		var xor []byte
		copy(xor, b_0)
		for j := range b_0 {
			xor[j] = b_0[j] ^ b_ell[len(b_ell)-1][j]
		}
		h.Write(util.Concat([][]byte{xor, pad, dst_prime}))
		var b_i = h.Sum([]byte{})

		b_ell = append(b_ell, b_i)
	}

	var uniform_bytes = util.Concat(b_ell)

	return uniform_bytes[0:uint64(byteslen)], nil
}

func (c *Curve) Hash2Field(message []byte, count int, dst []byte) ([][]uint64, error) {

	var lenb = count * c.m * c.l_maj

	var uniform_bytes, err1 = c.ExpandMsgXmd(message, lenb, dst)

	if err1 != nil {
		return nil, err1
	}

	var u_count [][]uint64
	for i := 0; i < count; i++ {
		var e_m = make([]uint64, 0)

		for j := 0; j < c.m; j++ {
			var elm_offset = c.l_maj * (j + i*c.m)
			var tv = util.Substr(uniform_bytes, uint(elm_offset), uint(c.l_maj))
			var e_j = util.OS2IP(tv, "") % uint64(c.prime)

			if c.m > 1 {
				e_m = append(e_m, e_j)
			} else {
				e_m[0] = e_j
			}
		}

		u_count = append(u_count, e_m)

	}
	return u_count, nil

}

func (c *Curve) ClearCofactor(q_maj any) any {
	return q_maj * c.cofactor
}

func (c *Curve) Encode(message []byte, dst []byte) (any, error) {
	var u, err1 = c.Hash2Field(message, 1, dst)
	if err1 != nil {
		return nil, err1
	}

	var q_maj = c.Map2Curve(int64(u[0]))

	var p_maj = c.ClearCofactor(q_maj)

	return p_maj
}

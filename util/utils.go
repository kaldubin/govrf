package util

import (
	"errors"
	"math/big"
)

var (
	ErrInt2bytestoolong = errors.New("ECVRF util: given value x is too large to be encoded to [xlen]bytes")
)

func CMOV(a int, b int, c bool) int {
	if c {
		return b
	} else {
		return a
	}
}

func Reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func I2SOP(x *big.Int, xlen int, byteorder string) ([]byte, error) {
	// fmt.Println(uint64(256**(xlen)))
	// if x >= uint64(math.Pow(256, float64(xlen+1))) {
	// 	return nil, ErrInt2bytestoolong
	// }

	var x_bytes = x.Bytes()
	var pad []byte
	if len(x_bytes) < xlen {
		pad = make([]byte, xlen-len(x_bytes))
	}

	if byteorder == "little" {
		Reverse[[]byte](x_bytes)
		x_bytes = append(x_bytes, pad...)
	} else {
		x_bytes = append(pad, x_bytes...)
	}
	return x_bytes, nil
}

func OS2IP(x []byte, byteorder string) *big.Int {

	var ret big.Int
	if byteorder == "little" {
		Reverse[[]byte](x)
	}

	ret.SetBytes(x)
	return &ret
}

func Substr(str []byte, begin uint, len uint) []byte {
	return str[begin : begin+len]
}

func Concat(slices [][]byte) []byte {
	var totlen int
	for _, s := range slices {
		totlen += len(s)
	}

	tmp := make([]byte, totlen)
	var i int
	for _, s := range slices {
		i += copy(tmp[i:], s)
	}

	return tmp
}

package util

import (
	"math"
	"math/big"
)

func Sgn0Meq1(x *big.Int) *big.Int {
	var sgn *big.Int
	return sgn.Mod(x, big.NewInt(2))
}

func IsSquare(x *big.Int, q *big.Int) bool {
	var x_pow *big.Int
	var exp *big.Int
	exp.Add(q, big.NewInt(-1))
	exp.Div(exp, big.NewInt(2))
	x_pow.Exp(x, exp, q)
	if x_pow.Cmp(big.NewInt(0)) == 0 || x_pow.Cmp(big.NewInt(1)) == 0 {
		return true
	}
	return false
}

func Inv0(x *big.Int, q *big.Int) *big.Int {
	var ret *big.Int
	var q_minus_2 *big.Int
	q_minus_2.Add(q, big.NewInt(-2))
	return ret.Exp(x, q_minus_2, q)
}

func LegendreSymbol(x int, q int) int {
	return int(math.Pow(float64(x), float64((q-1)/2))) % q
}

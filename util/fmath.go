package util

import "math"

func Sgn0Meq1(x int) int {
	return x % 2
}

func IsSquare(x int, q int) bool {
	var x_pow int = int(math.Pow(float64(x), float64((q-1)/2))) % q
	if x_pow == 0 || x_pow == 1 {
		return true
	}
	return false
}

func Inv0(x int, q int) int {
	return int(math.Pow(float64(x), float64(q-2))) % q
}

func LegendreSymbol(x int, q int) int {
	return int(math.Pow(float64(x), float64((q-1)/2))) % q
}

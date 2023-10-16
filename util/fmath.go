package util

import (
	"math/big"
)

func Sgn0Meq1(x *big.Int) *big.Int {
	var sgn = big.NewInt(0)
	return sgn.Mod(x, big.NewInt(2))
}

func IsSquare(x *big.Int, q *big.Int) bool {
	var x_pow = big.NewInt(0)
	var exp = big.NewInt(0)
	exp.Add(q, big.NewInt(-1))
	exp.Div(exp, big.NewInt(2))
	x_pow.Exp(x, exp, q)
	if x_pow.Cmp(big.NewInt(0)) == 0 || x_pow.Cmp(big.NewInt(1)) == 0 {
		return true
	}
	return false
}

func Inv0(x *big.Int, q *big.Int) *big.Int {
	var ret = big.NewInt(0)
	var q_minus_2 = big.NewInt(0)
	q_minus_2.Add(q, big.NewInt(-2))
	return ret.Exp(x, q_minus_2, q)
}

func LegendreSymbol(x *big.Int, q *big.Int) *big.Int {
	var ret, pow big.Int
	pow.Add(q, big.NewInt(-1))
	pow.Div(&pow, big.NewInt(2))
	return ret.Exp(x, &pow, q)
}

func Sqrt3mod4(x, p *big.Int) *big.Int {
	var c1 = big.NewInt(1)
	c1.Add(p, c1)
	c1.Div(c1, big.NewInt(4))

	var ret big.Int
	ret.Exp(x, c1, p)
	return &ret
}

func Sqrt(x, p *big.Int) *big.Int {
	if LegendreSymbol(x, p).Cmp(big.NewInt(1)) != 0 {
		return big.NewInt(0)
	} else if x.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0)
	}

	var s, s2 big.Int
	s.Add(p, big.NewInt(-1))
	var e = big.NewInt(0)

	for s2.Mod(&s, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		s.Div(&s, big.NewInt(2))
		e.Add(e, big.NewInt(1))
	}

	var n = big.NewInt(2)
	var cmp big.Int
	cmp.Add(p, big.NewInt(-1))
	for LegendreSymbol(n, p).Cmp(&cmp) != 0 {
		n.Add(n, big.NewInt(1))
	}

	var z, pow, b, g, r big.Int
	pow.Add(&s, big.NewInt(1))
	pow.Div(&pow, big.NewInt(2))
	z.Exp(x, &pow, p)
	b.Exp(x, &s, p)
	g.Exp(n, &s, p)
	r.Set(e)

	var t, m, gs big.Int
	max := 0
	for max < 10000 {
		max++

		t.Set(&b)
		m.SetInt64(0)
		for m.Cmp(&r) < 0 {
			if t.Cmp(big.NewInt(1)) == 0 {
				break
			}
			m.Add(&m, big.NewInt(1))
			t.Exp(&t, big.NewInt(2), p)
		}

		if m.Cmp(big.NewInt(0)) == 0 {
			return &z
		}

		gs.Sub(&r, &m)
		gs.Sub(&gs, big.NewInt(1))
		gs.Exp(big.NewInt(2), &gs, nil)
		gs.Exp(&g, &gs, p)

		g.Exp(&gs, big.NewInt(2), p)

		z.Mul(&z, &gs)
		z.Mod(&z, p)

		b.Mul(&b, &g)
		b.Mod(&b, p)

		r.Set(&m)
	}

	return big.NewInt(0)
}

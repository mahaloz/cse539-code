package mulproof

import (
	"math/big"

	"bitbucket.org/henrycg/riposte/prg"
	"bitbucket.org/henrycg/riposte/utils"
)

var one *big.Int
var two *big.Int

type ProofShare struct {
	F_0 *big.Int
	G_0 *big.Int
	H_0 *big.Int
	H_2 *big.Int
}

type AnsShare struct {
	F_R *big.Int
	G_R *big.Int
	H_R *big.Int
}

// Prove that a*b = c
func Prove(mod *big.Int, nShares int, a, b, c *big.Int) []ProofShare {
	/*
		tmp := new(big.Int)
		tmp.Mul(a, b)
		tmp.Mod(tmp, mod)
		if tmp.Cmp(c) != 0 {
			panic("Invalid")
		}*/

	f0 := utils.RandInt(mod)
	g0 := utils.RandInt(mod)
	h0 := new(big.Int)
	h2 := new(big.Int)

	// f(0) = f0    =>     f(X) = (A - f0)X + f0
	// f(1) = A
	// g(0) = g0		=>		 g(X) = (B - g0)X + g0
	// g(1) = B
	// h = f*g

	// Need to send point h(2)

	// Compute f(2), g(2)
	f2 := new(big.Int)
	g2 := new(big.Int)

	// f(2) = (A - f0)*2 + f0
	f2.Sub(a, f0)
	f2.Mul(f2, two)
	f2.Add(f2, f0)
	f2.Mod(f2, mod)

	// g(2) = (B - g0)*2 + g0
	g2.Sub(b, g0)
	g2.Mul(g2, two)
	g2.Add(g2, g0)
	g2.Mod(g2, mod)

	// h(0) = f(0) * g(0)
	h0.Mul(f0, g0)
	h0.Mod(h0, mod)

	// h(2) = f(2) * g(2)
	h2.Mul(f2, g2)
	h2.Mod(h2, mod)

	f0Shares := prg.Share(mod, nShares, f0)
	g0Shares := prg.Share(mod, nShares, g0)
	h0Shares := prg.Share(mod, nShares, h0)
	h2Shares := prg.Share(mod, nShares, h2)

	out := make([]ProofShare, nShares)
	for i := 0; i < nShares; i++ {
		out[i].F_0 = f0Shares[i]
		out[i].G_0 = g0Shares[i]
		out[i].H_0 = h0Shares[i]
		out[i].H_2 = h2Shares[i]
	}

	return out
}

// Produce linear queries to the proof share,
// using randomness r
func Query(mod, r *big.Int, pf *ProofShare,
	aShare, bShare, cShare *big.Int) *AnsShare {
	out := new(AnsShare)
	out.F_R = new(big.Int)
	out.G_R = new(big.Int)
	out.H_R = new(big.Int)

	// Compute shares of f(R), g(R), h(R)

	// f(R) = (A - f0)R + f0
	out.F_R.Sub(aShare, pf.F_0)
	out.F_R.Mul(out.F_R, r)
	out.F_R.Add(out.F_R, pf.F_0)
	out.F_R.Mod(out.F_R, mod)

	// g(R) = (B - g0)R + g0
	out.G_R.Sub(bShare, pf.G_0)
	out.G_R.Mul(out.G_R, r)
	out.G_R.Add(out.G_R, pf.G_0)
	out.G_R.Mod(out.G_R, mod)

	deg2Interp(mod, out.H_R, r, pf.H_0, cShare, pf.H_2)

	return out
}

func deg2Interp(mod, h_r, r, h0, h1, h2 *big.Int) {
	twoInv := new(big.Int)
	twoInv.SetUint64(2)
	twoInv.ModInverse(twoInv, mod)

	// Compute h(R) using Lagrange interpolation.
	// Let h0, h1, h2 be the evaluations of h at (0,1,2).
	//
	// Then
	// h(R) = (1/2)(R-1)(R-2)h0 - R(R-2)h1 + (1/2)R(R-1)h2
	v0 := new(big.Int)
	v1 := new(big.Int)
	v2 := new(big.Int)

	r1 := new(big.Int)
	r1.Sub(r, one)

	r2 := new(big.Int)
	r2.Sub(r, two)

	// v0 = (1/2)(R-1)(R-2)h0
	v0.Mul(twoInv, r1)
	v0.Mul(v0, r2)
	v0.Mul(v0, h0)

	// v1 = - R(R-2)h1
	v1.Mul(r, r2)
	v1.Mul(v1, h1)
	v1.Sub(mod, v1)

	// v2 = (1/2)R(R-1)h2
	v2.Mul(twoInv, r)
	v2.Mul(v2, r1)
	v2.Mul(v2, h2)

	// h(R) = v1 + v2 + v3
	h_r.Add(v0, v1)
	h_r.Add(h_r, v2)
	h_r.Mod(h_r, mod)
}

func Decide(mod *big.Int, pfs []*AnsShare) bool {
	n := len(pfs)
	fR := new(big.Int)
	gR := new(big.Int)
	hR := new(big.Int)

	for i := 0; i < n; i++ {
		fR.Add(fR, pfs[i].F_R)
		gR.Add(gR, pfs[i].G_R)
		hR.Add(hR, pfs[i].H_R)
	}
	fR.Mod(fR, mod)
	gR.Mod(gR, mod)
	hR.Mod(hR, mod)

	// Test f(R)*g(R) = h(R) ?
	fR.Mul(fR, gR)
	fR.Mod(fR, mod)

	return fR.Cmp(hR) == 0
}

func init() {
	one = new(big.Int)
	two = new(big.Int)

	one.SetUint64(1)
	two.SetUint64(2)
}

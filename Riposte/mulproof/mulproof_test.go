package mulproof

import (
	"math/big"
	"testing"

	"bitbucket.org/henrycg/riposte/prg"
	"bitbucket.org/henrycg/riposte/utils"
)

func TestMulProof(t *testing.T) {
	mod := new(big.Int)
	mod.SetUint64(18947925169)

	a := utils.RandInt(mod)
	b := utils.RandInt(mod)
	c := new(big.Int)
	c.Mul(a, b)
	c.Mod(c, mod)

	nShares := 5
	r := utils.RandInt(mod)
	aShares := prg.Share(mod, nShares, a)
	bShares := prg.Share(mod, nShares, b)
	cShares := prg.Share(mod, nShares, c)

	ansShares := make([]*AnsShare, nShares)
	pfShares := Prove(mod, nShares, a, b, c)
	for i := 0; i < nShares; i++ {
		ansShares[i] = Query(mod, r, &pfShares[i], aShares[i], bShares[i], cShares[i])
	}

	if !Decide(mod, ansShares) {
		t.Fail()
	}
}

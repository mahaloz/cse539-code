package prg

import (
	"math/big"

	"bitbucket.org/henrycg/riposte/utils"
)

// A server uses a ReplayPRG to recover the shared values
// that the client sent it (in the form of a PRGHints struct).
type ReplayPRG struct {
	rand *utils.BufPRGReader
	seed utils.PRGKey
	cur  int
}

// Produce a new ReplayPRG object for the given server/leader combo.
func NewReplayPRG() *ReplayPRG {
	out := new(ReplayPRG)
	return out
}

// Import the compressed secret-shared values from hints.
func (p *ReplayPRG) Import(seed utils.PRGKey) {
	p.seed = seed
	p.rand = utils.NewBufPRG(utils.NewPRG(&p.seed))
	p.cur = 0
}

// Recover a secret-shared value that is shared in a field
// that uses modulus mod.
func (p *ReplayPRG) Get(mod *big.Int) *big.Int {
	out := p.rand.RandInt(mod)
	p.cur++

	return out
}

// Split the value secret into two shares modulo mod.
func Share(mod *big.Int, nShares int, secret *big.Int) []*big.Int {
	out := make([]*big.Int, nShares)

	acc := new(big.Int)
	for i := 0; i < nShares-1; i++ {
		out[i] = utils.RandInt(mod)

		acc.Add(acc, out[i])
	}

	acc.Sub(secret, acc)
	acc.Mod(acc, mod)
	out[nShares-1] = acc

	return out
}

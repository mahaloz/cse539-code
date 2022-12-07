package prf

import (
	//  "encoding/binary"

	"crypto/aes"
	"crypto/cipher"

	"bitbucket.org/henrycg/riposte/utils"
)

// Length of PRF seed (in bytes)
const KEY_LENGTH = 16

type Key [KEY_LENGTH]byte

type Prf struct {
	block cipher.Block
}

func NewKey() (Key, error) {
	key := new(Key)
	utils.RandBytes(key[:])
	return *key, nil
}

func NewPrf(k Key) (Prf, error) {
	var p Prf
	var err error
	p.block, err = aes.NewCipher(k[:])
	return p, err
}

func (p *Prf) Evaluate(to_encrypt []byte) {
	// IV is all zeros (we will never use
	// this key again)
	iv := make([]byte, aes.BlockSize)

	// We are making the [unsafe] assumption that all blocks
	// are the same length.
	//iv_integer := block_idx * uint64(len(to_encrypt))
	//binary.PutUvarint(iv, iv_integer)

	stream := cipher.NewCTR(p.block, iv)
	stream.XORKeyStream(to_encrypt, to_encrypt)
}

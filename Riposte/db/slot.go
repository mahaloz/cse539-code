package db

import (
	"crypto/rand"
	//"log"
	"math/big"
	"reflect"
	"unsafe"

	"golang.org/x/crypto/poly1305"
)

func MessageToRow(msg *Plaintext) BitMatrixRow {
	var res BitMatrixRow
	start := SLOT_LENGTH * msg.X
	copy(res[start:], msg.Message[:])
	return res
}

func XorRows(dest, add *BitMatrixRow) {
	xorEq(dest[:], add[:])
}

func RandomSlot(slot *SlotContents) error {
	_, err := rand.Read(slot[:])
	return err
}

func HashSlot(hashKey *[32]byte, slot []byte) [16]byte {
	var out [16]byte
	//log.Printf("slot %v", slot)
	//log.Printf("key %v", hashKey)
	poly1305.Sum(&out, slot, hashKey)
	return out
}

func SlotToInt(out *big.Int, hashKey *[32]byte, slot []byte, modReduce bool) {
	h := HashSlot(hashKey, slot[:])
	//log.Printf("h=%v", h)
	out.SetBytes(h[:])
	if modReduce {
		out.Mod(out, IntModulus)
	}
}

/* Copied from
 * https://groups.google.com/forum/#!topic/golang-nuts/aPjvemV4F0U
 */

func xoreq64(a, b []uint64) {
	for i := range a {
		a[i] ^= b[i]
	}
}

// touint64 assumes len(x)%8 == 0
func touint64(x []byte) []uint64 {
	xx := make([]uint64, 0, 0)
	hdrp := (*reflect.SliceHeader)(unsafe.Pointer(&xx))
	hdrp.Data = (*reflect.SliceHeader)(unsafe.Pointer(&x)).Data
	hdrp.Len = len(x) / 8
	hdrp.Cap = len(x) / 8
	return xx
}

func xorEq(a, b []byte) {
	if len(a) != len(b) || len(a)%8 != 0 {
		panic("lengths not equal or not a multiple of 8")
	}

	xoreq64(touint64(a), touint64(b))
}

func tableToInts() {

}

package utils

import (
  "crypto/rand"
  "testing"
)

func TestSign(t *testing.T) {
  for i:=0; i<len(ServerCertificates); i++ {
    var buf [256]byte

    r, _ := rand.Read(buf[:])
    if r != 256 {
      t.Fail()
    }

    bufp := buf[:]

    sig := EcdsaSign(0, bufp)
    if !EcdsaVerify(0, bufp, sig) {
      t.Fail()
    }

    if EcdsaVerify(1, bufp, sig) {
      t.Fail()
    }

    buf[0] = buf[0] ^ 0xff
    if EcdsaVerify(0, bufp, sig) {
      t.Fail()
    }
  }
}

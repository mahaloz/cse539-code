package db

import (
  "crypto/rand"
  "testing"
)

func TestAddRows(t *testing.T) {
  var r1, r2 BitMatrixRow
  var err error
  _, err = rand.Read(r1[:])
  if err != nil {
    t.FailNow()
  }

  _, err = rand.Read(r2[:])
  if err != nil {
    t.FailNow()
  }

  var res BitMatrixRow
  XorRows(&res, &r1)
  XorRows(&res, &r2)

  for i := 0; i<len(r1); i++ {
    if res[i] != r1[i] ^ r2[i] {
      t.FailNow()
    }
  }
}

func TestMessageRow(t *testing.T) {
  var row, res BitMatrixRow
  msg, err := RandomSlot()
  if err != nil {
    t.FailNow()
  }

  xIdx := 2
  msgRow := MessageToRow(msg, xIdx)
  XorRows(&res, &msgRow)
  XorRows(&res, &row)
  for i := 0; i<len(msg); i++ {
    if res[(SLOT_LENGTH*xIdx) + i] != msg[i] {
      t.FailNow()
    }
  }
}

func BenchmarkMessageRow(b *testing.B) {
  var r, s BitMatrixRow
  rand.Read(r[:])
  rand.Read(s[:])
  for i := 0; i<b.N; i++ {
    XorRows(&r, &s)
  }
}


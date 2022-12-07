package db

import (
  "testing"
)

func TestArgsZeroNoProof(t *testing.T) {
  testOnce(t, 0, 0)
}

func TestArgsNonzeroNoProof(t *testing.T) {
  testOnce(t, 1, 1)
}


func testOnce(t *testing.T, xIdx, yIdx int) {
  var args UploadArgs
  var msg SlotContents
  msg = [SLOT_LENGTH]byte{123, 101}

  err := InitializeUploadArgs(&args, xIdx, yIdx, msg, false)
  if err != nil {
    t.Fail()
  }

  for serv := 0; serv<len(args.Query); serv++ {
    q := args.Query[serv]
    _, err := DecryptQuery(serv, q)
    if err != nil {
      t.Fail()
    }
  }
}


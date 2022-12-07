package db

import (
	"bitbucket.org/henrycg/riposte/prf"
	"bitbucket.org/henrycg/riposte/utils"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/poly1305"
)

func randomQuery(t *testing.T) InsertQuery {
	var q InsertQuery
	utils.RandVectorBool(q.Key.KeyMask[:])
	var err error
	for i := 0; i < len(q.Key.Keys); i++ {
		q.Key.Keys[i], err = prf.NewKey()
		if err != nil {
			t.FailNow()
		}
	}

	return q
}

func randomAudit(t *testing.T) AuditQuery {
	var q AuditQuery
	l := 128
	q.MsgTest = make([][poly1305.TagSize]byte, l)
	q.KeyTest = make([][poly1305.TagSize]byte, l)
	for i := range q.MsgTest {
		rand.Read(q.MsgTest[i][:])
		rand.Read(q.KeyTest[i][:])
	}
	return q
}

func TestEncryptGood(t *testing.T) {
	for i := 0; i < NUM_SERVERS; i++ {
		q := randomQuery(t)
		enc, err := EncryptQuery(i, q)
		if err != nil {
			t.Fatal("Could not encrypt")
		}

		dec, err := DecryptQuery(i, enc)
		if err != nil {
			t.Fatal("Decryption: ", err)
		}

		for j := 0; j < len(dec.Key.Keys); j++ {
			if dec.Key.Keys[j] != q.Key.Keys[j] {
				t.Fail()
			}
		}
	}
}

func TestEncryptAuditGood(t *testing.T) {
	q := randomAudit(t)
	enc, err := EncryptAudit(q)
	if err != nil {
		t.Fatal("Could not encrypt")
	}

	dec, err := DecryptAudit(enc)
	if err != nil {
		t.Fatal("Decryption: ", err)
	}

	for j := 0; j < len(q.KeyTest); j++ {
		if dec.KeyTest[j] != q.KeyTest[j] {
			t.Fail()
		}

		if dec.MsgTest[j] != q.MsgTest[j] {
			t.Fail()
		}
	}
}

func TestEncryptAuditBad(t *testing.T) {
	q := randomAudit(t)
	enc, err := EncryptAudit(q)
	if err != nil {
		t.Fatal("Could not encrypt")
	}

	enc.Ciphertext[3] = 0xff
	enc.Ciphertext[7] = 0xff

	_, err = DecryptAudit(enc)
	if err == nil {
		t.Fatal("Decryption should not be okay")
	}
}

func TestEncryptBad(t *testing.T) {
	for i := 0; i < NUM_SERVERS; i++ {

		q := randomQuery(t)
		enc, err := EncryptQuery(i, q)
		if err != nil {
			t.Fatal("Could not encrypt")
		}

		_, err = DecryptQuery((i+1)%NUM_SERVERS, enc)
		if err == nil {
			t.Fail()
		}
	}
}

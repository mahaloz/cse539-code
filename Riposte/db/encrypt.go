package db

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"

	"bitbucket.org/henrycg/riposte/utils"
	"golang.org/x/crypto/nacl/box"
)

func EncryptQuery(serverIdx int, query interface{}) (EncryptedInsertQuery, error) {
	var out EncryptedInsertQuery
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(query)
	if err != nil {
		return out, err
	}

	return encryptBytes(serverIdx, buf.Bytes())
}

func DecryptQuery(serverIdx int, enc EncryptedInsertQuery, output interface{}) error {
	buf, err := decryptBytes(serverIdx, enc)
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(bytes.NewBuffer(buf))
	return dec.Decode(output)
}

/*** Helper Functions ***/

func encryptBytes(serverIdx int, buf []byte) (EncryptedInsertQuery, error) {
	var out EncryptedInsertQuery
	serverPublicKey := utils.ServerBoxPublicKeys[serverIdx]
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return out, err
	}

	myPublicKey, myPrivateKey, err := box.GenerateKey(rand.Reader)

	out.SenderPublicKey = *myPublicKey
	out.Nonce = nonce
	out.Ciphertext = box.Seal(nil, buf, &nonce, serverPublicKey, myPrivateKey)

	/*
	  log.Printf("pk   %v", out.SenderPublicKey)
	  log.Printf("nc   %v", out.Nonce)
	  log.Printf("ct   %v", out.Ciphertext)
	*/

	return out, nil
}

func decryptBytes(serverIdx int, enc EncryptedInsertQuery) ([]byte, error) {
	serverPrivateKey := utils.ServerBoxPrivateKeys[serverIdx]

	var buf []byte
	buf, okay := box.Open(nil, enc.Ciphertext, &enc.Nonce,
		&enc.SenderPublicKey, serverPrivateKey)

	if !okay {
		return buf, errors.New("Could not decrypt")
	}

	return buf, nil
}

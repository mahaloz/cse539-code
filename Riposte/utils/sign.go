package utils

/****
 * WARNING!!! These are bogus keys for evaluation purposes only.
 * NEVER NEVER NEVER use these keys in a real deployment.
 */

import (
  "crypto/ecdsa"
  "crypto/rand"
  "crypto/sha256"
  "log"
  "math/big"
)

type EcdsaSignature struct {
  R []byte
  S []byte
}

func EcdsaSign(signerIdx int, msg []byte) EcdsaSignature {
  var sig EcdsaSignature
  cert := ServerCertificates[signerIdx]
  priv := cert.PrivateKey.(*ecdsa.PrivateKey)

  hash := sha256.Sum256(msg)
  r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
  if err != nil {
    log.Fatal("Signature failed: ", err)
  }

  sig.R = r.Bytes()
  sig.S = s.Bytes()

  return sig
}

func EcdsaVerify(signerIdx int, msg []byte, sig EcdsaSignature) bool{
  r := new(big.Int)
  s := new(big.Int)
  r.SetBytes(sig.R)
  s.SetBytes(sig.S)

  cert := ServerCertificates[signerIdx]
  pub := cert.PrivateKey.(*ecdsa.PrivateKey).PublicKey

  hash := sha256.Sum256(msg)
  return ecdsa.Verify(&pub, hash[:], r, s)
}


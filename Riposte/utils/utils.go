package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"bitbucket.org/henrycg/zkp/group"
)

var CommonCurve = group.CurveP256()

/*
func AllServers() []string {
  return []string {
    "localhost:9090",
    "localhost:9091",
    "localhost:9092",
    "localhost:9093",
    "localhost:8084",
    "localhost:8085",
    "localhost:8086",
    "localhost:8087",
  }
}

func NumServers() int {
  return len(AllServers())
}
*/

func RandomInt64(max int64) (int64, error) {
	var bigMax *big.Int = big.NewInt(int64(max))
	var out *big.Int
	var err error
	out, err = rand.Int(rand.Reader, bigMax)
	if err != nil {
		return 0, err
	}

	return out.Int64(), nil
}

func HashString(b []byte) *big.Int {
	h := sha256.Sum224(b)
	return new(big.Int).SetBytes(h[:])
}

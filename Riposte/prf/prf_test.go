package prf

import "testing"

func TestPrf(t *testing.T) {
  key, err := NewKey()
  if err != nil {
    t.FailNow()
  }

  prf, err := NewPrf(key)
  if err != nil {
    t.FailNow()
  }

  buf := make([]byte, 1<<8)
  prf.Evaluate(buf)
}

func BenchmarkPrf(b *testing.B) {
  c := make(chan int, b.N)

  for i := 0; i<b.N; i++ {
    go prfOnce(c)
  }

  for i := 0; i<b.N; i++ {
    <-c
  }
}

func prfOnce(c chan int) {
  key, _ := NewKey()
  prf, _ := NewPrf(key)

  buf := make([]byte, (1<<20))
  prf.Evaluate(buf)
  c <-0
}


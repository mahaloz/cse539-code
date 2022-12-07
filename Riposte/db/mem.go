package db

import (
  "fmt"
  "runtime"
)

func MemCleanup() {
  var stats runtime.MemStats

  pstat := func(tag string) {
  fmt.Printf("[%v] Mem in use: %v, System bytes: %v\n", tag, stats.Alloc, stats.Sys)

  }

  runtime.GC()

  runtime.ReadMemStats(&stats)
  pstat("Before GC")

  runtime.GC()

  runtime.ReadMemStats(&stats)
  pstat("After GC")
}


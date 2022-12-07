package db

import (
//  "fmt"
  "testing"
)

func TestSimple(t *testing.T) {
  tab := new(SlotTable)
  tab.ForeachRow(func(_ int, value *BitMatrixRow) {
    for i := 0; i<len(value); i++ {
      value[i] = 2
    }
  })

  if tab.table[0][0] != 2 {
    t.Fail()
  }

  tab.Clear()

  if tab.table[0][0] != 0 {
    t.Fail()
  }
}

func TestEndToEndNoProof(t *testing.T) {
  testEndToEndOnce(t)
}

func testEndToEndOnce(t *testing.T) {
  xIdx, yIdx, msg, err := RandomMessage()
  if err != nil {
    t.FailNow()
  }

  var args UploadArgs
  err = InitializeUploadArgs(&args, xIdx, yIdx, msg, false)
  if err != nil {
    t.FailNow()
  }
  //fmt.Printf("(x,y) = (%v, %v)\n", xIdx, yIdx)
  //fmt.Printf("msg = (%v)\n", msg)

  // Args has encrypted insert queries
  slotTables := make([]SlotTable, NUM_SERVERS)
  for i := 0; i<NUM_SERVERS; i++ {
    // Decrypt query
    var query *InsertQuery
    query, err = DecryptQuery(i, args.Query[i])
    if err != nil {
      t.FailNow()
    }

    // Add to table
    queries := make([]*InsertQuery, 1)
    queries[0] = query
    slotTables[i].processQueries(queries)
  }

  // Combine tables 
  replies := new([NUM_SERVERS]DumpReply)
  for i := 0; i<NUM_SERVERS; i++ {
    replies[i].Entries = new(BitMatrix)
    slotTables[i].CopyToAndClear(replies[i].Entries)
  }

  b := revealCleartext(*replies)
  for i:=0; i<len(b); i++ {
    for j:=0; j<len(b[i]); j++ {
      //fmt.Printf("%v ", b[i][j])
    }
    //fmt.Printf("\n")
  }

  var out [SLOT_LENGTH]byte
  copy(out[:], b[yIdx][(SLOT_LENGTH*xIdx):])
  if out != msg {
    t.Fatal("Message mismatch", out, msg)
  }
}

func BenchmarkTable(b *testing.B) {
  xIdx, yIdx, msg, err := RandomMessage()
  if err != nil {
    b.FailNow()
  }

  var args UploadArgs
  err = InitializeUploadArgs(&args, xIdx, yIdx, msg, false)
  if err != nil {
    b.FailNow()
  }

  // Decrypt query
  var query *InsertQuery
  query, err = DecryptQuery(0, args.Query[0])
  if err != nil {
    b.FailNow()
  }

  // Add to table
  queries := make([]*InsertQuery, b.N)
  for i := 0; i < b.N; i++ {
    queries[i] = query
  }

  // Args has encrypted insert queries
  slotTable := new(SlotTable)
  b.ResetTimer()

  slotTable.processQueries(queries)
}


package db

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net/rpc"
	"time"

	"bitbucket.org/henrycg/riposte/mulproof"
	"bitbucket.org/henrycg/riposte/utils"
	"bitbucket.org/henrycg/zkp/group"
)

// Time to wait between merges (in seconds)
const MERGE_TIME_DELAY time.Duration = 14 * 3600

// Time to wait between printing stats (in seconds)
const STATS_DELAY time.Duration = 10

// Number of pending requests that leader can buffer
const READY_BUFFER_SIZE = 400

// Number of server-side requests to allow in flight
const WORKER_THREADS = 16

func (t *Server) isLeader() bool {
	return (t.ServerIdx == 0)
}

/*******************
 * Leader code
 */

func (t *Server) Upload1(args *UploadArgs1, reply *UploadReply1) error {
	if !t.isLeader() {
		return errors.New("Only leader can accept uploads")
	}
	<-t.incoming1

	//log.Printf("Got upload request")
	//log.Printf("Request:", args)

	uuid, err := utils.RandomInt64(math.MaxInt64)
	if err != nil {
		log.Printf("error in random")
		return err
	}

	tup := new(AcceptQueryTuple)
	tup.args1 = args

	// In a secure implementation, these bytes would be derived pseudorandomly
	// from a seed picked collaboratively by all of the servers in a one-time
	// setup phase.
	utils.RandBytes(tup.hashKey[:])
	utils.RandBytes(tup.challenge[:])

	reply.Uuid = uuid
	copy(reply.HashKey[:], tup.hashKey[:])

	t.acceptedMutex.Lock()
	t.accepted[uuid] = tup
	t.acceptedMutex.Unlock()
	t.incoming1 <- true

	return nil
}

func (t *Server) Upload2(args *UploadArgs2, reply *UploadReply2) error {
	if !t.isLeader() {
		return errors.New("Only leader can accept uploads")
	}
	<-t.incoming2

	//log.Printf("Got Upload2 request")

	t.acceptedMutex.Lock()
	data, okay := t.accepted[args.Uuid]
	if okay {
		data.args2 = args
		copy(reply.Challenge[:], data.challenge[:])
	}
	t.acceptedMutex.Unlock()

	if !okay || !bytes.Equal(data.hashKey[:], args.HashKey[:]) {
		return errors.New("Bogus UUID")
	}

	//log.Printf("Upload2 OK")
	t.incoming2 <- true
	return nil
}

func (t *Server) Upload3(args *UploadArgs3, reply *UploadReply3) error {
	if !t.isLeader() {
		return errors.New("Only leader can accept uploads")
	}
	<-t.incoming3

	//log.Printf("Got Upload3 request")
	//log.Printf("Request:", args)

	t.acceptedMutex.Lock()
	data, okay := t.accepted[args.Uuid]
	if okay {
		data.args3 = args
	}
	t.acceptedMutex.Unlock()

	if !okay || !bytes.Equal(data.hashKey[:], args.HashKey[:]) {
		return errors.New("Bogus UUID")
	}

	t.ready <- args.Uuid
	t.incoming3 <- true

	return nil
}

// Do everything
func (t *Server) processRequest() {
	for {
		uuid := <-t.ready
		t.amPublishingMutex.RLock()

		t.clientsServedMutex.Lock()
		t.clientsServed += 1
		t.clientsServedMutex.Unlock()

		shouldCommit := t.submitPrepares(uuid)
		t.submitCommits(uuid, shouldCommit)

		t.amPublishingMutex.RUnlock()
	}
}

func readIncomingRequests(preps *[NUM_SERVERS]PrepareArgs,
	c chan [NUM_SERVERS]EncryptedInsertQuery) bool {
	queryList := <-c
	if queryList[0].Ciphertext == nil {
		return true
	}

	for i := 0; i < NUM_SERVERS; i++ {
		(*preps)[i].Query1 = queryList[i]
	}

	return false
}

func (t *Server) submitPrepares(uuid int64) bool {
	var preps [NUM_SERVERS]PrepareArgs
	t.acceptedMutex.Lock()
	tup := t.accepted[uuid]
	delete(t.accepted, uuid)
	t.acceptedMutex.Unlock()

	randPt := utils.RandInt(IntModulus)
	for i := 0; i < NUM_SERVERS; i++ {
		preps[i].Uuid = uuid
		preps[i].RandomPoint = randPt
		copy(preps[i].HashKey[:], tup.hashKey[:])
		copy(preps[i].Challenge[:], tup.challenge[:])
		preps[i].Query1 = tup.args1.Query[i]
		preps[i].Query2 = tup.args2.Query[i]
		preps[i].Query3 = tup.args3.Query[i]
	}

	//log.Printf("Send PREPARE %d", uuid)

	// Send out PREPARE request
	c := make(chan error, NUM_SERVERS)
	var replies [NUM_SERVERS]PrepareReply
	for i := 0; i < NUM_SERVERS; i++ {
		go func(prep *PrepareArgs, reply *PrepareReply, j int) {
			err := t.rpcClients[j].Call("Server.Prepare", prep, reply)
			if err != nil {
				c <- err
			} else {
				c <- nil
			}
		}(&preps[i], &replies[i], i)
	}

	// Wait for responses
	var r error
	for i := 0; i < NUM_SERVERS; i++ {
		r = <-c
		if r != nil {
			log.Fatal("Error in prepare: ", r)
		}
	}

	out := new(big.Int)
	for i := 0; i < NUM_SERVERS; i++ {
		out.Add(out, replies[i].OutShare)
	}

	out.Mod(out, IntModulus)

	if out.Sign() != 0 {
		log.Printf("FAIL!!!!!!!! <<<<< 1")
	}

	proofs1 := make([]*mulproof.AnsShare, NUM_SERVERS)
	proofs2 := make([]*mulproof.AnsShare, NUM_SERVERS)
	for i := 0; i < NUM_SERVERS; i++ {
		proofs1[i] = replies[i].AnsShare1
		proofs2[i] = replies[i].AnsShare2
	}

	if !mulproof.Decide(IntModulus, proofs1) {
		log.Printf("Proof 1 FAIL!!!!!!!! <<<<< :(")
	}

	if !mulproof.Decide(IntModulus, proofs2) {
		log.Printf("Proof 2 FAIL!!!!!!!! <<<<< :(")
	}

	okay := true
	return okay
}

func (t *Server) submitCommits(uuid int64, shouldCommit bool) {
	var com CommitArgs
	com.Uuid = uuid
	com.Commit = shouldCommit

	//log.Printf("Send COMMIT %d", com.Uuid)

	// Send out COMMIT request
	c := make(chan error, NUM_SERVERS)
	var replies [NUM_SERVERS]CommitReply
	for i := 0; i < NUM_SERVERS; i++ {
		go func(com *CommitArgs, reply *CommitReply, j int) {
			err := t.rpcClients[j].Call("Server.Commit", com, reply)
			if err != nil {
				c <- err
			} else {
				c <- nil
			}
		}(&com, &replies[i], i)
	}

	// Wait for responses
	var r error
	for i := 0; i < NUM_SERVERS; i++ {
		r = <-c
		if r != nil {
			log.Fatal("Error in commit: ", r)
		}
		//log.Printf("Got commit %v/%v", i, NUM_SERVERS)
	}

	//log.Printf("Done COMMIT %d", com.Uuid)
}

func (t *Server) mergeWorker() {
	for {
		log.Printf("Mergeworker starts")
		time.Sleep(MERGE_TIME_DELAY * time.Second)
		log.Printf("Mergeworker fire!")
		t.sendMergeRequest()
	}
}

func (t *Server) printStats() {
	for {
		time.Sleep(STATS_DELAY * time.Second)
		t.clientsServedMutex.Lock()
		t.clientsTotal += t.clientsServed

		rate := float64(t.clientsServed) / float64(STATS_DELAY)
		t.rateHistory = append(t.rateHistory, rate)
		// Keep last 10
		t.rateHistory = t.rateHistory[1:]
		t.clientsServedMutex.Unlock()

		log.Printf("Served %v requests at %v reqs/sec [since start: %v]", t.clientsServed, rate, t.clientsTotal)
		rateStr := "Rate_History ["
		for i := 0; i < len(t.rateHistory); i++ {
			rateStr = fmt.Sprintf("%v %f", rateStr, t.rateHistory[i])
		}
		rateStr = fmt.Sprintf("%v]", rateStr)
		log.Printf("%v", rateStr)

		t.clientsServed = 0
	}
}

func (t *Server) sendMergeRequest() {
	t.acceptedMutex.Lock()

	// Call each server and ask for their data
	// Send out COMMIT request
	c := make(chan error, NUM_SERVERS)
	var replies [NUM_SERVERS]DumpReply
	for i := 0; i < NUM_SERVERS; i++ {
		go func(reply *DumpReply, j int) {
			err := t.rpcClients[j].Call("Server.DumpTable", 0, reply)
			if err != nil {
				c <- err
			} else {
				c <- nil
			}
		}(&replies[i], i)
	}

	// Wait for responses
	var r error
	for i := 0; i < NUM_SERVERS; i++ {
		r = <-c
		if r != nil {
			log.Fatal("Error in merge: ", r)
		}
		log.Printf("Done merge")
	}

	var parg PlaintextArgs
	parg.Plaintext = revealCleartext(replies)

	var p_reply PlaintextReply
	err := t.rpcClients[0].Call("Server.StorePlaintext", &parg, &p_reply)

	if err != nil {
		log.Fatal("Error in plaintext: ", r)
	}

	log.Printf("Done MERGE")
	t.acceptedMutex.Unlock()
	//MemCleanup()
}

func revealCleartext(tables [NUM_SERVERS]DumpReply) *BitMatrix {
	b := new(BitMatrix)

	// XOR all of the tables together and save
	// it in the plaintext table
	//log.Printf("Revealing cleartext")
	for serv := 0; serv < NUM_SERVERS; serv++ {
		for i := 0; i < TABLE_HEIGHT; i++ {
			XorRows(&b[i], &tables[serv].Entries[i])
		}
	}
	//log.Printf("Done revealing cleartext")

	return b
}

/**************
 * Handle Updates
 */

func (t *Server) Prepare(prep *PrepareArgs, reply *PrepareReply) error {
	tup := new(InsertQueryTuple)

	copy(tup.hashKey[:], prep.HashKey[:])
	copy(tup.challenge[:], prep.Challenge[:])
	err := DecryptQuery(t.ServerIdx, prep.Query1, &tup.q1)
	if err != nil {
		panic("Decryption error")
	}

	err = DecryptQuery(t.ServerIdx, prep.Query2, &tup.q2)
	if err != nil {
		panic("Decryption error")
	}

	err = DecryptQuery(t.ServerIdx, prep.Query3, &tup.q3)
	if err != nil {
		panic("Decryption error")
	}

	t.pendingMutex.Lock()
	t.pending[prep.Uuid] = tup
	t.pendingMutex.Unlock()

	reply.OutShare = new(big.Int)
	reply.OutShare.Sub(tup.q3.TShare1, tup.q3.TShare2)
	reply.OutShare.Mod(reply.OutShare, IntModulus)

	zShare1 := new(big.Int)
	zShare2 := new(big.Int)
	t.entries.processQuery(tup, reply, t.ServerIdx == 1, zShare1, zShare2)

	// Check that t1 = z1^2
	reply.AnsShare1 = mulproof.Query(IntModulus, prep.RandomPoint, &tup.q3.TProof1,
		zShare1, zShare1, tup.q3.TShare1)

	// Check that t2 = m*z2
	reply.AnsShare2 = mulproof.Query(IntModulus, prep.RandomPoint, &tup.q3.TProof2,
		tup.q2.MsgShare, zShare2, tup.q3.TShare2)

	return nil
}

func (t *Server) Commit(com *CommitArgs, reply *CommitReply) error {
	t.pendingMutex.Lock()
	_, ok := t.pending[com.Uuid]
	t.pendingMutex.Unlock()

	if !ok {
		err := errors.New(fmt.Sprintf("Got commit msg for unknown UUID: %d", com.Uuid))
		return err
	}

	if !com.Commit {
		// Remove query from the database, since it
		// was malformed.
		log.Printf("Removing bogus query %v from DB", com.Uuid)

		panic("Got bogus query")
		// XXX: In a production implementation, we would expand
		// the DPF key and remove this bogus update to the database
		// by XORing the DPF key back into the database shares.
	}

	t.pendingMutex.Lock()
	delete(t.pending, com.Uuid)
	t.pendingMutex.Unlock()

	return nil
}

func (t *Server) StorePlaintext(args *PlaintextArgs, reply *PlaintextReply) error {
	//log.Printf("Storing plaintext")
	t.plainMutex.Lock()
	t.plain = args.Plaintext

	/*
		var zeros SlotContents
		for i := range t.plain {
			for j := 0; j < len(t.plain[i]); j += SLOT_LENGTH {
				msg := t.plain[i][j:(j + SLOT_LENGTH)]
				if bytes.Compare(zeros[:], msg) != 0 {
					log.Printf("Got msg: %v", msg)
				}
			}
		}

		t.plainMutex.Unlock()
	*/

	//MemCleanup()
	return nil
}

func (t *Server) DumpTable(_ *int, reply *DumpReply) error {
	log.Printf("Dumping table %d\n", t.ServerIdx)
	reply.Entries = new(BitMatrix)
	t.entries.CopyToAndClear(reply.Entries)
	return nil
}

/*
func (t *Server) DumpPlaintext(_ *int, reply *DumpReply) error {
  t.plainMutex.Lock()
  reply.Entries = t.plain
  t.plainMutex.Unlock()
  return nil
}
*/

/***********
 * Initialization
 */

func (t *Server) connectToServer(client **rpc.Client, serverAddr string, remoteIdx int, c chan error) {
	var err error
	certs := []tls.Certificate{utils.ServerCertificates[remoteIdx]}
	*client, err = utils.DialHTTPWithTLS("tcp", serverAddr, t.ServerIdx, certs)
	c <- err
}

func (t *Server) openConnections() error {
	log.Printf("Waiting 2 seconds for other servers to boot")
	time.Sleep(1000 * time.Millisecond)

	if !t.isLeader() {
		return errors.New("Only leader should open connections")
	}

	c := make(chan error, len(t.ServerAddrs))
	for i := range t.ServerAddrs {
		go t.connectToServer(&t.rpcClients[i], t.ServerAddrs[i], i, c)
	}

	// Wait for all connections
	failed := false
	for i := 0; i < len(t.ServerAddrs); i++ {
		err := <-c
		if err != nil {
			log.Printf("Error connecting to server: %v", err)
		}
	}

	if failed {
		return errors.New("Connection failed")
	}

	return nil
}

func (t *Server) Initialize(*int, *int) error {
	if t.isLeader() {
		t.incoming1 = make(chan bool, READY_BUFFER_SIZE)
		t.incoming2 = make(chan bool, READY_BUFFER_SIZE)
		t.incoming3 = make(chan bool, READY_BUFFER_SIZE)
		t.ready = make(chan int64, READY_BUFFER_SIZE)
		go t.mergeWorker()
		go t.printStats()

		for i := 0; i < WORKER_THREADS; i++ {
			go t.processRequest()
		}

		for i := 0; i < READY_BUFFER_SIZE; i++ {
			t.incoming1 <- true
			t.incoming2 <- true
			t.incoming3 <- true
		}

		go func(t *Server) {
			// HACK wait until other servers have started
			time.Sleep(500 * time.Millisecond)
			err := t.openConnections()
			if err != nil {
				log.Fatal("Could not initialize table", err)
			}
		}(t)
	}
	return nil
}

func elementsToBytes(elms []group.Element) []byte {
	var buf bytes.Buffer
	for i := 0; i < len(elms); i++ {
		buf.Write(utils.CommonCurve.Marshal(elms[i]))
	}

	return buf.Bytes()
}

/*
func (t *Server) Download(args *DownloadArgs, reply *DownloadReply) error {
  log.Printf("Got download request")
  log.Printf("Request:", args)

  if !RangeIsValid(t, args.RequestedSlot) {
    return errors.New("Out of range")
  }

  var slot = &t.Entries[args.RequestedSlot]
  log.Printf("idx: ", args.RequestedSlot)

  slot.Mutex.Lock()
  if slot.IsFilled {
    reply.Data.Buffer = slot.Data.Buffer
  }
  slot.Mutex.Unlock()

  return nil
}
*/

func NewServer(serverIdx int, serverAddrs []string) *Server {
	t := new(Server)
	t.entries = NewSlotTable()
	t.plain = new(BitMatrix)
	t.ServerIdx = serverIdx
	t.ServerAddrs = serverAddrs
	t.rateHistory = make([]float64, 10)
	t.pending = map[int64](*InsertQueryTuple){}
	t.accepted = map[int64](*AcceptQueryTuple){}

	return t
}

func (t *Server) DoNothing(args *int, reply *int) error {
	// Just use this to test number
	// of requests can handle in a second
	t.acceptedMutex.Lock()
	t.clientsServed++
	log.Printf("Served %v", t.clientsServed)
	t.acceptedMutex.Unlock()

	return nil
}

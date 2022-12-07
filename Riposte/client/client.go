package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/rpc"
	"os"
	"runtime"
	"sync"

	//"bytes"
	//"encoding/gob"

	"bitbucket.org/henrycg/riposte/db"
	"bitbucket.org/henrycg/riposte/utils"
)

var donothingFlag = flag.Bool("donothing", false, "If set, client pings server.")
var bogusFlag = flag.Bool("bogus", false, "If set, client sends an invalid request.")
var hammerFlag = flag.Bool("hammer", false, "If set, client sends requests to server as quickly as possible.")
var leaderFlag = flag.String("leader", "", "Leader IP and port")
var logFlag = flag.String("log", "", "Location of log file")
var threadsFlag = flag.Uint("threads", 1, "Number of threads to use")

var countLock sync.Mutex
var count int

func tryUpload(client *rpc.Client, msg *db.Plaintext) error {
	var upRes1 db.UploadReply1
	var upArgs1 db.UploadArgs1

	msgBitShares, err := db.InitializeUploadArgs(&upArgs1, msg, *bogusFlag)
	if err != nil {
		panic("Error initializing upload args")
	}

	//var buf []byte
	//b := bytes.NewBuffer(buf)
	//g := gob.NewEncoder(b)
	//g.Encode(upArgs1)
	//log.Printf("Buffer len %v", b.Len())

	err = client.Call("Server.Upload1", &upArgs1, &upRes1)
	if err != nil {
		log.Printf("Error:", err)
		return err
	}

	var upRes2 db.UploadReply2
	mint, upArgs2 := db.SetUploadArgs2(msgBitShares, &upArgs1, &upRes1)

	// Get second msg
	err = client.Call("Server.Upload2", &upArgs2, &upRes2)
	if err != nil {
		log.Printf("Error:", err)
		return err
	}

	var upRes3 db.UploadReply3
	upArgs3 := db.SetUploadArgs3(msg, mint, &upArgs1, &upRes1, upArgs2, &upRes2)

	// Get third msg
	err = client.Call("Server.Upload3", &upArgs3, &upRes3)
	if err != nil {
		log.Printf("Error:", err)
		return err
	}

	return nil
}

func tryDumpTable(client *rpc.Client) db.DumpReply {
	var tab db.DumpReply
	err := client.Call("Server.DumpPlaintext", 0, &tab)
	if err != nil {
		log.Printf("Error:", err)
	}

	return tab
}

func runClient(server string, msg *db.Plaintext, tab *db.DumpReply) {
	certs := make([]tls.Certificate, 1)
	certs[0] = utils.LeaderCertificate
	client, err := utils.DialHTTPWithTLS("tcp", server, -1, certs)
	defer client.Close()
	if err != nil {
		log.Printf("Could not connect:", err)
		return
	}

	//log.Printf("Connected")
	for {
		c := -1
		countLock.Lock()
		count += 1
		c = count
		countLock.Unlock()

		if c%100 == 0 {
			log.Printf("Sent %v requests", c)
		}

		if *donothingFlag {
			var a, b int
			err := client.Call("Server.DoNothing", &a, &b)
			if err != nil {
				panic("Oh no!")
			}

		} else {
			err = tryUpload(client, msg)
			if err != nil {
				log.Printf("Upload error", err)
				return
			}
		}

		if !*hammerFlag {
			break
		}
	}
}

func clientOnce(bogus bool) {
	var table db.DumpReply

	if *donothingFlag {
		runClient(*leaderFlag, nil, &table)
	} else {
		//log.Printf("=== Starting Client ===")
		msg, err := db.RandomMessage()

		if err != nil {
			log.Printf("Error generating message: ", err)
			return
		}

		//log.Printf("Insert into [%v,%v]", xIdx, yIdx)
		//log.Printf("Plaintext [%v]", msg)
		runClient(*leaderFlag, msg, &table)
	}
}

func main() {
	flag.Parse()
	if *leaderFlag == "" {
		log.Fatal("Must specify leader.\n")
	}

	if *logFlag != "" {
		f, ferr := os.OpenFile(*logFlag, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664)
		if ferr != nil {
			log.Fatal("Could not open log file ", *logFlag)
		}
		log.SetOutput(f)
	}

	log.SetPrefix("[Client ] ")

	runtime.GOMAXPROCS(int(*threadsFlag))

	defer log.Printf("Client died.")

	c := make(chan int, 1)
	// Make one request
	if !*hammerFlag {
		clientOnce(*bogusFlag)
	} else {
		// Make many requests concurrently
		concurrent := 16
		for i := 0; i < concurrent; i++ {
			go clientOnce(*bogusFlag)
		}

		// Wait forever
		<-c
	}
}

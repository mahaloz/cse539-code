package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
)

import (
	"bitbucket.org/henrycg/riposte/db"
	"bitbucket.org/henrycg/riposte/utils"
)

var flagProfile = flag.Bool("profile", false, "Run CPU profiler")
var flagIndex = flag.Int("idx", -1, "Server index")
var flagLog = flag.String("log", "", "Log file")
var flagThreads = flag.Int("threads", -1, "Number of threads to use")

// List of server addresses
type serverListType []string

var serverList serverListType

func (s *serverListType) String() string {
	return fmt.Sprint(*s)
}

// Comma-separated list of server addresses (ip:port)
func (s *serverListType) Set(value string) error {
	if len(*s) > 0 {
		return errors.New("server flag already set")
	}

	for _, dt := range strings.Split(value, ",") {
		*s = append(*s, dt)
	}
	return nil
}

func init() {
	flag.Var(&serverList, "servers", "Comma-separated list of servers (in \"ip:port\" form)")
}

func main() {
	flag.Parse()

	if *flagLog != "" {
		f, ferr := os.OpenFile(*flagLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664)
		if ferr != nil {
			log.Fatal("Could not open log file ", *flagLog)
			os.Exit(1)
		}
		log.SetOutput(f)
	}

	if *flagIndex < 0 {
		log.Fatal("Must server index must be greater than zero")
		return
	}

	idx := *flagIndex

	if len(serverList) < 1 || idx > len(serverList)-1 {
		log.Fatal("Must specify a list of servers")
		return
	}

	if *flagThreads > 0 {
		runtime.GOMAXPROCS(int(*flagThreads))
	}

	defer log.Printf("Server died.")

	log.SetPrefix(fmt.Sprintf("[Server %v] ", idx))

	if *flagProfile {
		f, err := os.Create(fmt.Sprintf("server-%v.prof", idx))
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)

		// Stop when process exits
		defer pprof.StopCPUProfile()

		// Stop on ^C
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		signal.Notify(c, os.Kill)
		go func() {
			for _ = range c {
				// sig is a ^C, handle it
				pprof.StopCPUProfile()
				os.Exit(0)
			}
		}()
	}

	var a int
	slotTable := db.NewServer(idx, serverList)
	slotTable.Initialize(&a, &a)
	rpc.Register(slotTable)

	var certs []tls.Certificate

	// If we are not the leader, only allow
	// connections from the leader
	if idx > 0 {
		certs = append(certs, utils.LeaderCertificate)
	}

	utils.ListenAndServe(serverList[idx], idx, certs)
	log.Printf("Server %d is listening at %s", idx, serverList[idx])

	//http.ListenAndServe(addr, nil)
}

package main

import (
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

func readAll(p io.ReadCloser) {
	for {
		var str [1024]byte
		p.Read(str[:])
		fmt.Printf("> %s", str)
	}
}

func main() {
	var servers = []string{
		"localhost:9090",
		"localhost:9091",
		//"localhost:9092",
	}

	s := strings.Join(servers, ",")

	var procs []*exec.Cmd = make([]*exec.Cmd, len(servers))
	for i := range servers {
		log.Printf("Starting server: %v", servers[i])
		procs[i] = exec.Command("./server", "-profile", "-servers", s, "-idx", strconv.Itoa(i))
		stdout, err := procs[i].StdoutPipe()
		stderr, err := procs[i].StderrPipe()
		go readAll(stdout)
		go readAll(stderr)
		err = procs[i].Start()
		if err != nil {
			log.Printf("Process %v error: %v", i, err.Error())
		}
	}

	for i := 0; i < len(servers); i++ {
		err := procs[i].Wait()
		if err != nil {
			log.Printf("Process %v error: %v", i, err.Error())
		}
	}
}

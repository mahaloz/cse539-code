// Implements a basic control program for managing a
// Riposte deployment on EC2.
package main

import (
	"fmt"
	"log"
	"os"
)

const LOCAL_GOBIN = "/Users/henrycg/go/bin"
const EC2_USER = "ubuntu"
const EC2_KEY = "~/.ssh/amazon/henrycg-mbarara2.pem"

var sshOptions []string

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %v <command>", os.Args[0])
	}

	switch os.Args[1] {
	case "kill":
		runKill()
	case "killc":
		runKillClients()
	case "start":
		runStart()
	case "startc":
		runStartClients()
	case "startdc":
		runStartDummyClients()
	case "logs":
		runLogs()
	case "copy":
		runCopy()
	case "rmlogs":
		runRmlogs()

	default:
		log.Fatal("Unrecognized command.")
	}
}

func init() {
	sshOptions = []string{
		"-o", fmt.Sprintf("User=%v", EC2_USER),
		"-o", "StrictHostKeyChecking=no",
		"-i", EC2_KEY}
}

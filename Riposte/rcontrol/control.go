package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
)

var SERVER_IPS [2]string = [...]string{"34.200.221.83", "54.157.103.123"}
var SERVER_PORTS [2]string = [...]string{"9090", "9091"}

var CLIENT_IPS [2]string = [...]string{"3.228.1.182", "3.228.19.14"}

type commandFunc func(serverIdx int) string
type fileFunc func(serverIdx int, host string) []string

func runRemote(command string, argsIn []string) {
	args := append(sshOptions, argsIn...)
	log.Printf("%v", args)
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Error: ", err)
	}
}

func runAt(hosts []string, do commandFunc) {
	n := len(hosts)
	c := make(chan int, n)
	for i := 0; i < n; i++ {
		go func(j int) {
			runRemote("ssh", []string{hosts[j], do(j)})
			c <- 0
		}(i)
	}

	for i := 0; i < n; i++ {
		<-c
	}
}

func getHost(i int) string {
	return SERVER_IPS[i] //fmt.Sprintf("%v:%v", SERVER_IPS[i], SERVER_PORTS[i])
}

func getServers() []string {
	servers := make([]string, 2)
	servers[0] = getHost(0)
	servers[1] = getHost(1)
	return servers
}

func getClients() []string {
	out := make([]string, len(CLIENT_IPS))
	for i := 0; i < len(CLIENT_IPS); i++ {
		out[i] = CLIENT_IPS[i]
	}
	return out
}

func runAtServers(do commandFunc) {
	runAt(getServers(), do)
}

func runAtClients(do commandFunc) {
	runAt(getClients(), do)
}

func copyToHosts(hosts []string, src, dst fileFunc) {
	n := len(hosts)
	c := make(chan int, n)
	for i := 0; i < n; i++ {
		go func(j int) {
			args := append(src(j, hosts[j]), dst(j, hosts[j])...)
			runRemote("scp", args)
			c <- 0
		}(i)
	}

	for i := 0; i < n; i++ {
		<-c
	}

	log.Printf("Done.")
}

func copyToServers(src, dst fileFunc) {
	copyToHosts(getServers(), src, dst)
}

func copyToClients(src, dst fileFunc) {
	copyToHosts(getClients(), src, dst)
}

func runKill() {
	runAtServers(func(int) string {
		return "killall -s INT server"
	})
}

func runKillClients() {
	runAtClients(func(int) string {
		return "killall -s INT client"
	})
}

func runStart() {
	runAtServers(func(i int) string {
		trickleStr := ""
		if i == 1 {
			trickleStr = "trickle -s -d 12500 -u 12500"
		}
		return fmt.Sprintf("%v ~/server -idx %v -log /tmp/log-%v.log -servers %v:%v,%v:%v",
			trickleStr,
			i, i, SERVER_IPS[0], SERVER_PORTS[0], SERVER_IPS[1], SERVER_PORTS[1])
	})
}

func runStartClients() {
	runAtClients(func(i int) string {
		return fmt.Sprintf("~/client -threads 16 -log /tmp/client-%v.log -hammer -leader %v:%v", i, SERVER_IPS[0], SERVER_PORTS[0])
	})
}

func runStartDummyClients() {
	runAtClients(func(i int) string {
		return fmt.Sprintf("~/client -hammer -threads 16 -log /tmp/client-%v.log -hammer -leader %v:%v", i, SERVER_IPS[0], SERVER_PORTS[0])
	})
}

func runLogs() {
	src := func(k int, h string) []string { return []string{fmt.Sprintf("%v:/tmp/log-%v.log", h, k)} }
	dst := func(k int, h string) []string { return []string{fmt.Sprintf("log-%v.log", k)} }

	copyToServers(src, dst)
}

func runRmlogs() {
	runAtServers(func(i int) string {
		return fmt.Sprintf("rm /tmp/log-%v.log", i)
	})
	runAtClients(func(i int) string {
		return fmt.Sprintf("rm /tmp/client-%v.log", i)
	})
}

func runCopy() {
	src := func(k int, h string) []string {
		return []string{
			path.Join(LOCAL_GOBIN, "server"),
		}
	}

	clientSrc := func(k int, h string) []string {
		return []string{
			path.Join(LOCAL_GOBIN, "client"),
		}
	}

	dst := func(k int, h string) []string {
		return []string{fmt.Sprintf("%v:~", h)}
	}

	copyToServers(src, dst)
	copyToClients(clientSrc, dst)

	/*
		runAtClients(func(int) string {
			return fmt.Sprintf("mv %v config.conf", path.Join("~", path.Base(os.Args[1])))
		})

		runAtServers(func(int) string {
			return fmt.Sprintf("mv %v config.conf", path.Join("~", path.Base(os.Args[1])))
		})
	*/
}

/*
func runCopyConfig() {
	src := func(k int, h string) []string {
		return []string{os.Args[1]}
	}

	clientSrc := func(k int, h string) []string {
		return []string{os.Args[1]}
	}

	dst := func(k int, h string) []string {
		return []string{fmt.Sprintf("%v:~", h)}
	}

	copyToServers(src, dst)
	copyToClients(clientSrc, dst)

	runAtClients(func(int) string {
		return fmt.Sprintf("mv %v config.conf", path.Join("~", path.Base(os.Args[1])))
	})

	runAtServers(func(int) string {
		return fmt.Sprintf("mv %v config.conf", path.Join("~", path.Base(os.Args[1])))
	})
}
*/

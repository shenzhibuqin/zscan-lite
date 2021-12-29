package main

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

var (
	AliveHosts  []string
	OS          = runtime.GOOS
	pingsuccess sync.WaitGroup
)

func PingCheck(hosts []net.IP) []net.IP{
	if noPing {
		return hosts
	}else {
		checkedList := RunCheck(hosts)
		checkedString:=strings.Join(checkedList,",")
		res,_ :=ParseHosts(checkedString)
		return res
	}
}

func RunCheck(hostslist []net.IP) []string {
	Output(fmt.Sprintf("\n\r=========================living ip result list==========================\n"))
	chanHosts := make(chan string, 255)
	go func() {
		for ip := range chanHosts {
			Output(fmt.Sprintf("[ping] Find %v aliving\n",ip))
			AliveHosts = append(AliveHosts, ip)
			pingsuccess.Done()
		}
	}()

	RunPing(hostslist, chanHosts)

	pingsuccess.Wait()
	close(chanHosts)
	Output(fmt.Sprintf("A total of %v IP addresses were discovered\n",len(AliveHosts)))
	return AliveHosts
}

func RunPing(hostslist []net.IP, chanHosts chan string) {

	var wg sync.WaitGroup
	limiter := make(chan struct{},50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host) {
				pingsuccess.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host.String())
	}
	wg.Wait()
}

func ExecCommandPing(ip string) bool {
	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1000 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "linux" {
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	} else if OS == "darwin" {
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" >/dev/null && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") {
			return true
		} else {
			return false
		}
	}
}
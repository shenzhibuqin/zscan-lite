package main

import (
	"bytes"
	"fmt"
	"github.com/malfunkt/iprange"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

func ParseHosts(ipString string) ([]net.IP, error) {
	list, err := iprange.ParseList(ipString)
	if err != nil {
		return nil, err
	}
	iplist := list.Expand()
	return iplist, nil
}

func Output(context string) {
	fmt.Print(context)

	file, err := os.OpenFile(Outputfile, os.O_APPEND|os.O_WRONLY, 0666)
	defer file.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = file.Write([]byte(context))
	if err != nil {
		fmt.Println(err.Error())
	}
}

func CreatFile() error {
	if Hosts == "" {
		return nil
	}
	if Outputfile == "" {
		Outputfile = filename_filter(Hosts) + ".txt"
	}
	_, err := os.Stat(Outputfile)
	if err != nil {
		file, err := os.Create(Outputfile)
		if err != nil {
			return err
		}
		defer file.Close()
	}
	return nil
}

func filename_filter(filename string) string {
	f := func(c rune) rune {
		special := "\\/:*?<>|"
		if strings.Contains(special, string(c)) {
			return '_'
		}
		return c
	}
	return strings.Map(f, filename)
}

func ParsePorts(selection string) ([]int, error) {
	ports := make([]int, 0)
	if selection == "" {
		return ports, nil
	}

	ranges := strings.Split(selection, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port selection segment: '%s'", r)
			}

			p1, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[0])
			}

			p2, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", parts[1])
			}

			if p1 > p2 {
				return nil, fmt.Errorf("invalid port range: %d-%d", p1, p2)
			}

			for i := p1; i <= p2; i++ {
				ports = append(ports, i)
			}

		} else {
			if port, err := strconv.Atoi(r); err != nil {
				return nil, fmt.Errorf("invalid port number: '%s'", r)
			} else {
				ports = append(ports, port)
			}
		}
	}
	return ports, nil
}

func Getconn(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, Timeout)
}

func sortip(iplist []net.IP) []net.IP {
	sort.Slice(iplist, func(i, j int) bool {
		return bytes.Compare(iplist[i], iplist[j]) < 0
	})
	return iplist
}

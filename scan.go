package main

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

var httptitleResult sync.Map

func Startscan(hosts []net.IP, ports []int) {
	hosts = PingCheck(hosts)
	var p *Scan
	p = NewPortScan(hosts, ports)
	r := p.Run()
	PrintResult(r)
}

type Openport struct {
	ip     string
	port   []int
	banner map[int]string
}

type Scan struct {
	iplist     []net.IP
	ports      []int
	wg         sync.WaitGroup
	portscanch chan IpPort
	winscanch  chan net.IP
	result     map[string]*Openport
	tmpResult  sync.Map
	tasknum    float64
	donenum    float64
}

type IpPort struct {
	ip   string
	port int
}

type HttpInfo struct {
	Host    string
	Ports   string
	Url     string
	Timeout time.Duration
	title   string
	code    int
}

func NewPortScan(iplist []net.IP, ports []int) *Scan {
	return &Scan{
		iplist:     iplist,
		ports:      ports,
		portscanch: make(chan IpPort, Thread*2),
		winscanch: make(chan net.IP, Thread*2),
		result:     make(map[string]*Openport),
		tasknum:    float64(len(iplist)*len(ports) + len(iplist)),
	}
}

func (p *Scan) Run() map[string]*Openport {
	go p.GetPortscanTaskList()
	for i := 0; i < Thread; i++ {
		go p.GoPortscan()
	}
	go p.GetWinscanTaskList()
	for i := 0; i < Thread; i++ {
		go p.GoWinscan()
	}
	go p.bar()
	time.Sleep(time.Second)
	p.wg.Wait()
	p.GetResult()
	return p.result
}

func (p *Scan) GetPortscanTaskList() {
	p.wg.Add(1)
	defer p.wg.Done()
	for _, port := range p.ports {
		for _, ip := range p.iplist {
			ipPort := IpPort{ip: ip.String(), port: port}
			p.portscanch <- ipPort
		}
	}
	close(p.portscanch)
}

func (p *Scan) GoPortscan() {
	p.wg.Add(1)
	defer p.wg.Done()
	for ipPort := range p.portscanch {
		p.SaveResult(StartPortScan(ipPort.ip, ipPort.port))
		p.donenum += 1
	}
}

func (p *Scan) GetWinscanTaskList() {
	p.wg.Add(1)
	defer p.wg.Done()
	for _, ip := range p.iplist {
		p.winscanch <- ip
	}
	close(p.winscanch)
}

func (p *Scan) GoWinscan() {
	p.wg.Add(1)
	defer p.wg.Done()
	for ip := range p.winscanch {
		p.SaveResult(StartWinScan(ip.String()))
		p.donenum += 1
	}
}

func (p *Scan) SaveResult(ip string, port int, banner string, err error) {
	if err != nil {
		return
	}
	v, ok := p.tmpResult.Load(ip)
	if ok {
		ports, ok1 := v.(map[int]string)
		if ok1 {
			ports[port] = banner
			p.tmpResult.Store(ip, ports)
		}
	} else {
		ports := make(map[int]string, 0)
		ports[port] = banner
		p.tmpResult.Store(ip, ports)
	}
}

func (p *Scan) GetResult() {
	p.tmpResult.Range(func(key, value interface{}) bool {
		v, ok := value.(map[int]string)
		if ok {
			port := []int{}
			for i := range v {
				port = append(port, i)
			}
			sort.Ints(port)
			b := make(map[int]string)
			for _, i := range port {
				b[i] = v[i]
			}
			p.result[key.(string)] = &Openport{ip: key.(string), port: port, banner: b}
		}
		return true
	})
}

func (p *Scan) bar() {
	for {
		for _, r := range `-\|/` {
			fmt.Printf("\r%c portscan:%4.2f%v %c", r, float64(p.donenum/p.tasknum*100), "%", r)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func PrintResult(r map[string]*Openport) {
	Output(fmt.Sprintf("\n\r============================port result list=============================\n"))
	Output(fmt.Sprintf("There are %v IP addresses in total\n", len(r)))
	realIPs := make([]net.IP, 0, len(r))
	for ip := range r {
		realIPs = append(realIPs, net.ParseIP(ip))
	}
	for _, i := range sortip(realIPs) {
		Output(fmt.Sprintf("Traget:%v\n", i))
		for _, p := range r[i.String()].port {
			banner := r[i.String()].banner[p]
			if len(banner) > 0 {
				if p == 0 {
					Output(fmt.Sprintf("%v\n",banner))
				} else {
					Output(fmt.Sprintf("  %v Banner:%v\n", p, banner))
				}
			} else if p!=0 {
				Output(fmt.Sprintf("  %v\n", p))
			}
		}
	}
	Output(fmt.Sprintf("============================http result list=============================\n"))
	httptitleResult.Range(func(key, value interface{}) bool {
		Output(fmt.Sprintf("Traget:%v\n", key))
		v, ok := value.(*HttpInfo)
		if ok {
			fmt.Print(v.Url)
			Output(fmt.Sprintf("  code:%v", v.code))
			Output(fmt.Sprintf("  title:%v", v.title))
			fmt.Print("\n\n")
		}
		return true
	})
}

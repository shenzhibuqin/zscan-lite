package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var httptitleResult sync.Map

type ConnectMethod func(ip string, port int) (string, int, string, error)

func Portscan(hosts []net.IP, ports []int) {
	hosts=PingCheck(hosts)
	var p *PortScan
	p = NewPortScan(hosts, ports, ConnectPort)
	r := p.Run()
	Printresult(r)
}

type Openport struct {
	ip     string
	port   []int
	banner map[int]string
}

type PortScan struct {
	iplist          []net.IP
	ports           []int
	wg              sync.WaitGroup
	taskch          chan IpPort
	resultch        chan []string
	tcpconn         ConnectMethod
	result          map[string]*Openport
	portscan_result sync.Map
	tasknum         float64
	donenum         float64
}

type IpPort struct {
	ip   string
	port int
}

type HttpInfo struct {
	Host      string
	Ports     string
	Url       string
	Timeout   time.Duration
	title	  string
	code      int
}

func NewPortScan(iplist []net.IP, ports []int, connect ConnectMethod) *PortScan {
	return &PortScan{
		iplist:   iplist,
		ports:    ports,
		taskch:   make(chan IpPort, Thread*2),
		tcpconn:  connect,
		resultch: make(chan []string, Thread*2),
		result:   make(map[string]*Openport),
		tasknum:  float64(len(iplist) * len(ports)),
	}
}

func (p *PortScan) Run() map[string]*Openport {
	go p.Gettasklist()
	for i := 0; i < Thread; i++ {
		go p.Startscan()
	}
	go p.bar()
	time.Sleep(time.Second)
	p.wg.Wait()
	p.Getresult()
	return p.result
}

func (p *PortScan) Gettasklist() {
	p.wg.Add(1)
	defer p.wg.Done()
	for _, port := range p.ports {
		for _, ip := range p.iplist {
			ipPort := IpPort{ip: ip.String(), port: port}
			p.taskch <- ipPort
		}
	}
	close(p.taskch)
}

func (p *PortScan) Startscan() {
	p.wg.Add(1)
	defer p.wg.Done()
	for ipPort := range p.taskch {
		p.SaveResult(p.tcpconn(ipPort.ip, ipPort.port))
		p.donenum += 1
	}
}

func (p *PortScan) SaveResult(ip string, port int, banner string, err error) {
	if err != nil {
		return
	}
	v, ok := p.portscan_result.Load(ip)
	if ok {
		ports, ok1 := v.(map[int]string)
		if ok1 {
			ports[port] = banner
			p.portscan_result.Store(ip, ports)
		}
	} else {
		ports := make(map[int]string, 0)
		ports[port] = banner
		p.portscan_result.Store(ip, ports)
	}
}

func (p *PortScan) Getresult() {
	p.portscan_result.Range(func(key, value interface{}) bool {
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

func (p *PortScan) bar() {
	for {
		for _, r := range `-\|/` {
			fmt.Printf("\r%c portscan:%4.2f%v %c", r, float64(p.donenum/p.tasknum*100), "%", r)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func Printresult(r map[string]*Openport) {
	Output(fmt.Sprintf("\n\r============================port result list=============================\n"))
	Output(fmt.Sprintf("There are %v IP addresses in total\n", len(r)))
	realIPs := make([]net.IP, 0, len(r))
	for ip := range r {
		realIPs = append(realIPs, net.ParseIP(ip))
	}
	for _, i := range sortip(realIPs) {
		Output(fmt.Sprintf("Traget:%v\n", i))
		for _, p := range r[i.String()].port {
			banner:=r[i.String()].banner[p]
			if len(banner) > 0 {
				Output(fmt.Sprintf("  %v Banner:%v\n", p,banner))
			} else {
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

func ConnectPort(ip string, port int) (string, int, string, error) {
	conn, err := Getconn(fmt.Sprintf("%v:%v", ip, port))
	if conn != nil {
		defer conn.Close()
		err := conn.SetReadDeadline(time.Now().Add(Timeout))
		if err != nil {
			return "", 0, "", err
		}
		reader := bufio.NewReader(conn)
		banner, _ := reader.ReadString('\r')
		banner = strings.Replace(banner, "\n", "", -1)
		Output(fmt.Sprintf("\rFind port %v:%v\r\n", ip, port))
		getWebTitle(&HttpInfo{Host: ip, Ports: fmt.Sprintf("%v", port), Timeout: Timeout * 2})
		return ip, port, banner, err
	}
	return ip, port, "", err
}

func getWebTitle(info *HttpInfo) {
	if info.Ports == "80" {
		info.Url = fmt.Sprintf("http://%s", info.Host)
	} else if info.Ports == "443" {
		info.Url = fmt.Sprintf("https://%s", info.Host)
	} else {
		host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
		protocol := GetProtocol(host, info.Timeout)
		info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
	}

	err := getTitle(info)
	if err != nil {
		return
	}

	httptitleResult.Store(fmt.Sprintf("%v:%v", info.Host, info.Ports), info)
}

func GetProtocol(host string, Timeout time.Duration) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: Timeout}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	protocol := "http"
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}

func getTitle(info *HttpInfo) error {
	req, err := http.NewRequest("GET", info.Url, nil)
	if err == nil {
		req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		req.Header.Set("Connection", "close")

		var client = &http.Client{
			Timeout:   Timeout,
		}

		resp, err := client.Do(req)

		if err == nil {
			defer resp.Body.Close()
			var title string
			var text []byte
			body, err := getRespBody(resp)
			if err != nil {
				return err
			}

			re := regexp.MustCompile("(?ims)<title>(.*)</title>")
			find := re.FindSubmatch(body)
			if len(find) > 1 {
				text = find[1]
				encode := GetEncoding(resp,body)
				var encode2 string
				detector := chardet.NewTextDetector()
				detectorstr, _ := detector.DetectBest(body)
				if detectorstr != nil {
					encode2 = detectorstr.Charset
				}
				if encode == "gbk" || encode == "gb2312" || strings.Contains(strings.ToLower(encode2), "gb") {
					titleGBK, err := Decodegbk(text)
					if err == nil {
						title = string(titleGBK)
					}
				} else {
					title = string(text)
				}
			} else {
				title = ""
			}
			title = strings.Trim(title, "\r\n \t")
			title = strings.Replace(title, "\n", "", -1)
			title = strings.Replace(title, "\r", "", -1)
			title = strings.Replace(title, "&nbsp;", " ", -1)
			if len(title) > 100 {
				title = title[:100]
			}
			info.title=title
			info.code=resp.StatusCode

			return nil
		}
		return err
	}
	return err
}

func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := ioutil.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

 func GetEncoding(resp *http.Response,body []byte) string {
 	Charsets := []string{"utf-8", "gbk", "gb2312"}
	r1, err := regexp.Compile(`(?im)charset=\s*?([\w-]+)`)
	if err != nil {
		return ""
	}
	headerCharset := r1.FindString(resp.Header.Get("Content-Type"))
	if headerCharset != "" {
		for _, v := range Charsets {
			if strings.Contains(strings.ToLower(headerCharset), v) == true {
				return v
			}
		}
	}

	r2, err := regexp.Compile(`(?im)<meta.*?charset=['"]?([\w-]+)["']?.*?>`)
	if err != nil {
		return ""
	}
	htmlCharset := r2.FindString(string(body))
	if htmlCharset != "" {
		for _, v := range Charsets {
			if strings.Contains(strings.ToLower(htmlCharset), v) == true {
				return v
			}
		}
	}
	return ""
}

func Decodegbk(s []byte) ([]byte, error) { // GBK解码
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}
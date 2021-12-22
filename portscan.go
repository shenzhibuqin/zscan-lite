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
	"strings"
	"time"
)

func StartPortScan(ip string, port int) (string, int, string, error) {
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
			Timeout: Timeout,
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
				encode := GetEncoding(resp, body)
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
			info.title = title
			info.code = resp.StatusCode

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

func GetEncoding(resp *http.Response, body []byte) string {
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
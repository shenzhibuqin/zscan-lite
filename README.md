# zscan-lite

## 编译命令
git clone https://github.com/shenzhibuqin/zscan-lite.git

cd 对应目录

go mod tidy

go build -ldflags "-s -w"


## usage

```
  -H string
        set Hosts eg:127.0.0.1/24,192.168.0.1-18
  -T int
        set threads eg:400 (default 500)
  -noping
        noping before port scan,default ping
  -o string
        set output file eg:res.txt
  -p string
        set ports eg:53-110,8080
  -t duration
        set timeout eg:2s (default 3s)
```
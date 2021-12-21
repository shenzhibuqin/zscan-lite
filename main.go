package main

import (
	"flag"
	"fmt"
	"time"
)

var Hosts string
var ports string
var Thread int
var Timeout time.Duration
var Ping bool
var Outputfile string

var defaultports="7,11,13,15,17,19,21,22,23,26,37,38,43,49,51,53,67,70,79,80,81,82,83,84,85,86,88,89,102,104,111,113,119,121,135,138,139,143,175,179,199,211,264,311,389,443,444,445,465,500,502,503,505,512,515,548,554,564,587,631,636,646,666,771,777,789,800,801,873,880,902,992,993,995,1000,1022,1023,1024,1025,1026,1027,1080,1089,1099,1177,1194,1200,1201,1234,1241,1248,1260,1290,1311,1344,1400,1433,1471,1494,1505,1515,1521,1588,1720,1723,1741,1777,1863,1883,1911,1935,1962,1967,1991,2000,2001,2002,2020,2022,2030,2049,2080,2082,2083,2086,2087,2096,2121,2181,2222,2223,2252,2323,2332,2375,2376,2379,2401,2404,2424,2455,2480,2501,2601,2628,3000,3128,3260,3288,3299,3306,3307,3310,3333,3388,3389,3390,3460,3541,3542,3689,3690,3749,3780,4000,4022,4040,4063,4064,4369,4443,4444,4505,4506,4567,4664,4712,4730,4782,4786,4840,4848,4880,4911,4949,5000,5001,5002,5006,5007,5009,5050,5084,5222,5269,5357,5400,5432,5555,5560,5577,5601,5631,5672,5678,5800,5801,5900,5901,5902,5903,5938,5984,5985,5986,6000,6001,6068,6379,6488,6560,6565,6581,6588,6590,6664,6665,6666,6667,6668,6669,6998,7000,7001,7005,7014,7071,7077,7080,7288,7401,7443,7474,7493,7537,7547,7548,7634,7657,7777,7779,7890,7911,8000,8001,8008,8009,8010,8020,8025,8030,8040,8060,8069,8080,8081,8082,8086,8087,8088,8089,8090,8098,8099,8112,8123,8125,8126,8139,8161,8200,8291,8333,8334,8377,8378,8443,8500,8545,8554,8649,8686,8800,8834,8880,8883,8888,8889,8983,9000,9001,9002,9003,9009,9010,9042,9051,9080,9090,9100,9151,9191,9200,9295,9333,9418,9443,9527,9530,9595,9653,9700,9711,9869,9944,9981,9999,10000,10001,10162,10243,10333,10808,11001,11211,11300,11310,12300,12345,13579,14000,14147,14265,15672,16010,16030,16992,16993,17000,18001,18081,18245,18246,19999,20000,20547,22105,22222,23023,23424,25000,25105,25565,27015,27017,28017,32400,33338,33890,37215,37777,41795,42873,45554,49151,49152,49153,49154,49155,50000,50050,50070,50100,51106,52869,55442,55553,60001,60010,60030,61613,61616,62078,64738"

func main(){
	//fmt.Print(" ______     ______     ______     ______     __   __    \n/\\___  \\   /\\  ___\\   /\\  ___\\   /\\  __ \\   /\\ \"-.\\ \\   \n\\/_/  /__  \\ \\___  \\  \\ \\ \\____  \\ \\  __ \\  \\ \\ \\-.  \\  \n  /\\_____\\  \\/\\_____\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_\\\\\"\\_\\ \n  \\/_____/   \\/_____/   \\/_____/   \\/_/\\/_/   \\/_/ \\/_/   --lite\n")


	flag.IntVar(&Thread, "T", 100, "set threads eg:400")
	flag.DurationVar(&Timeout, "t", time.Second*3, "set timeout eg:2s")
	flag.StringVar(&Hosts, "H", "", "set Hosts eg:127.0.0.1/24,192.168.0.1-18")
	flag.StringVar(&ports, "p", "", "set ports eg:53-110,8080")
	flag.BoolVar(&Ping,"noping",true,"noping before port scan,default ping")
	flag.StringVar(&Outputfile,"o","","set output file eg:res.txt")
	flag.Parse()

	err:=CreatFile()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if ports=="" {
		ports=defaultports
	}

	Hosts,err := ParseHosts(Hosts)
	if err!=nil {
		fmt.Println(err.Error())
		return
	}
	Ports,err := ParsePorts(ports)
	if err!=nil {
		fmt.Println(err.Error())
		return
	}
	Portscan(Hosts,Ports)
}

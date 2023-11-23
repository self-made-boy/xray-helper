package xray

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	log "github.com/golang/glog"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"xray-helper/common"
)

var CurrentXrayApp *XrayApp

var PrefixTest = "009_test_"

var PrefixProxy = "009_proxy_"

type XrayApp struct {
	config  common.XrayConfig
	Process *os.Process
	V2Rays  []*V2Ray
	testMu  sync.Mutex
	startMu sync.Mutex
	killMu  sync.Mutex
}

func NewXrayApp(config common.XrayConfig) *XrayApp {
	CurrentXrayApp = &XrayApp{config: config}
	return CurrentXrayApp
}

func (app *XrayApp) Start() error {
	err := app.DoStart()
	if err != nil {
		return err
	}
	err = app.TestAll()
	if err != nil {
		log.Errorf("test all config failed %v", err)
	} else {
		app.Restart(false)
	}

	return nil
}

func (app *XrayApp) DoStart() error {
	locked := app.startMu.TryLock()
	if !locked {
		return nil
	}
	defer app.startMu.Unlock()
	err := app.InitConfig()
	if err != nil {
		return err
	}
	err = app.Subscribe(false)
	if err != nil {
		return err
	}

	err = app.Run()
	if err != nil {
		return err
	}
	return nil
}

func (app *XrayApp) TestAll() error {
	locked := app.testMu.TryLock()
	if !locked {
		return nil
	}
	defer app.testMu.Unlock()

	costTimeMap := make(map[*V2Ray]int)

	var wg sync.WaitGroup
	resultCh := make(chan struct {
		v    *V2Ray
		cost int
	}, len(app.V2Rays))

	s := app.V2Rays
	if len(app.V2Rays) != 0 {
		for _, v := range s {

			wg.Add(1)
			go func(v *V2Ray) {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("test timeout: %v", r)
					}
				}()
				defer wg.Done()
				cost := app.Test(v)
				log.Infof("test complete, %v:%v", v.Ps, cost)
				resultCh <- struct {
					v    *V2Ray
					cost int
				}{v: v, cost: cost}
			}(v)
		}
	}

	go func() {
		timeout := time.After(20 * time.Second)
		// 这是一个用于等待所有goroutine完成的channel
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		// 使用一个select语句来等待done或timeout信号
		select {
		case <-done:
		// 如果done channel关闭，那么这个case变为可选择的，这表明所有的任务已经完成
		case <-timeout:
			// 如果从timeout channel中接收到值，那么这个case变为可选择的，这表明已经超时
			log.Infof("timed out waiting for test tasks to finish")
		}

		// 不论是所有任务已经完成，还是已经超时，我们都关闭resultCh，以便于接收结果的goroutine可以结束
		close(resultCh)
	}()

	for result := range resultCh {
		costTimeMap[result.v] = result.cost
	}

	err := app.RemoveFiles(PrefixProxy)
	if err != nil {
		return err
	}

	var available []*V2Ray
	for k, v := range costTimeMap {
		if v > 0 {
			available = append(available, k)
		}
	}

	sort.Slice(available, func(i, j int) bool {
		return costTimeMap[available[i]] < costTimeMap[available[j]]
	})
	if len(available) > 5 {
		available = available[:5]
	}
	for _, v := range available {
		err := app.V2rayToOutboundProxy(v)
		if err != nil {
			log.Errorf("V2rayToOutboundProxy error %v", err)
			continue
		}
	}

	return nil
}

func (app *XrayApp) Test(v *V2Ray) int {
	proxyUrlStr := "http://127.0.0.1:" + strconv.Itoa(int(app.config.TestPort))
	proxyUrl, err := url.Parse(proxyUrlStr)
	if err != nil {
		log.Errorf("proxy url parse error %v", err)
		return -1
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyUrl),
	}

	client := &http.Client{
		Transport: transport,
	}
	request, err := http.NewRequest("GET", "http://www.google.com/ncr", nil)
	if err != nil {
		log.Errorf("http NewRequest error %v", err)
		return -1
	}
	source := url.QueryEscape(v.GetTag("test_"))
	request.Header.Set("source", source)

	now := time.Now().UnixMilli()
	response, err := client.Do(request)
	cost := time.Now().UnixMilli() - now
	if err != nil {
		log.Errorf("test failed: %s call google filed  %v", v.GetTag("test_"), err)
		return -1
	}
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		log.Errorf("test failed: %s StatusCode is %v ", v.GetTag("test_"), response.StatusCode)
		return -1
	}
	return int(cost)
}
func (app *XrayApp) Run() error {
	xrayExe := filepath.Join(app.config.XrayExeDir, "xray")
	cmd := exec.Command(xrayExe, "run", "-confdir", app.config.XrayConfigDir)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+app.config.XrayAssetDir)
	stdout, _ := cmd.StdoutPipe()
	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			log.Infof("stuout if xray ------- %s", scanner.Text())
		}
	}()
	err := cmd.Start()
	if err != nil {
		return err
	}
	app.Process = cmd.Process

	time.Sleep(2 * time.Second)
	if cmd.ProcessState.ExitCode() != -1 {
		return errors.New("xray start failed")
	}

	return nil
}

func (app *XrayApp) InitConfig() error {
	err := app.InitApiConfig()
	if err != nil {
		return err
	}
	err = app.InitLogConfig()
	if err != nil {
		return err
	}

	err = app.InitDnsConfig()
	if err != nil {
		return err
	}

	err = app.InitPolicyConfig()
	if err != nil {
		return err
	}

	err = app.InitInboundConfig()
	if err != nil {
		return err
	}
	err = app.InitBaseOutboundConfig()
	if err != nil {
		return err
	}
	err = app.InitRouteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (app *XrayApp) InitRouteConfig() error {
	templateText := `
{
    "routing": {
        "domainStrategy": "AsIs",
        "domainMatcher": "hybrid",
        "rules": [
            {
                "type": "field",
                "domain": [
{{range .DomainWhitelist}}
                    "{{.}}",
{{end}}
                    "geosite:apple-cn",
                    "geosite:google-cn",
                    "geosite:cn",
                    "geosite:geolocation-cn"
                ],
                "ip": [],
                "network": "tcp",
                "source": [],
                "user": [],
                "inboundTag": ["inbounds-socks","inbounds-http"],
                "protocol": [],
                "attrs": {},
                "outboundTag": "direct"
            },
            {
                "type": "field",
                "domain": [],
                "ip": [
                    "0.0.0.0/8",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "114.114.114.114/32",
                    "fc00::/7",
                    "fe80::/10",
                    "geoip:private",
                    "geoip:cn"
                ],
                "network": "tcp",
                "source": [],
                "user": [],
                "inboundTag": ["inbounds-socks","inbounds-http"],
                "protocol": [],
                "attrs": {},
                "outboundTag": "direct"
            },
            {
                "type": "field",
                "domain": [
{{range .DomainBlacklist}}
                    "{{.}}",
{{end}}
                    "geosite:geolocation-!cn"
                ],
                "ip": [],
                "network": "tcp",
                "source": [],
                "user": [],
                "inboundTag": ["inbounds-socks","inbounds-http"],
                "protocol": [],
                "attrs": {},
                "balancerTag": "proxy-balancer"
            },
            {
                "type": "field",
                "domain": [],
                "ip": [
                    "geoip:!cn"
                ],
                "network": "tcp",
                "source": [],
                "user": [],
                "inboundTag": ["inbounds-socks","inbounds-http"],
                "protocol": [],
                "attrs": {},
                "balancerTag": "proxy-balancer"
            },
            {
                "type": "field",
                "inboundTag": [
                    "api"
                ],
                "outboundTag": "api"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads",
                    "geosite:category-ads-all"
                ],
                "ip": [],
                "network": "tcp,udp",
                "source": [],
                "user": [],
                "inboundTag": [],
                "protocol": [],
                "attrs": {},
                "outboundTag": "blocked"
            }
        ],
        "balancers": [
            {
                "tag": "proxy-balancer",
                "selector": [
                    "proxy"
                ]
            }
        ]
    }
}
`
	t := template.New("route template")
	_, err := t.Parse(templateText)
	if err != nil {
		return err
	}

	config := app.config
	var buf bytes.Buffer
	err = t.Execute(&buf, config)
	if err != nil {
		return err
	}

	data := buf.String()
	fileName := "006route.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	err = writeToFile(data, filePath)
	if err != nil {
		return err
	}
	return nil
}
func (app *XrayApp) InitBaseOutboundConfig() error {
	data := `
{
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        },
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "api"
        }
  ]
}

`
	fileName := "006base_outbound.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	err := writeToFile(data, filePath)
	if err != nil {
		return err
	}
	return nil
}

func (app *XrayApp) InitInboundConfig() error {
	templateText := `
{
    "inbounds": [
      {
        "listen": "127.0.0.1",
        "port": {{.SocksPort}},
        "protocol": "socks",
        "settings": {},
        "streamSettings": {},
        "tag": "inbounds-socks",
        "sniffing": {
          "enabled": true,
          "destOverride": ["http", "tls"]
        },
        "allocate": {
          "strategy": "always"
        }
      },
      {
        "listen": "127.0.0.1",
        "port": {{.HttpPort}},
        "protocol": "http",
        "settings": {},
        "streamSettings": {},
        "tag": "inbounds-http",
        "sniffing": {
          "enabled": true,
          "destOverride": ["http", "tls"]
        },
        "allocate": {
          "strategy": "always"
        }
      },
      {
        "port": {{.ApiPort}}, 
        "listen": "127.0.0.1", 
        "protocol": "dokodemo-door",
        "settings": {
            "address": "127.0.0.1"
        },
        "tag": "api"
    },
    {
      "listen": "127.0.0.1",
      "port": {{.TestPort}},
      "protocol": "http",
      "settings": {},
      "streamSettings": {},
      "tag": "inbounds-test",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "allocate": {
        "strategy": "always"
      }
    }
    ]
  }
`
	t := template.New("inbound template")
	_, err := t.Parse(templateText)
	if err != nil {
		return err
	}

	config := app.config
	var buf bytes.Buffer
	t.Execute(&buf, config)

	data := buf.String()
	fileName := "005inbound.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	err = writeToFile(data, filePath)
	if err != nil {
		return err
	}
	return nil
}

func (app *XrayApp) InitPolicyConfig() error {
	data := `
{
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "statsUserUplink": false,
                "statsUserDownlink": false
            }
        },
        "system": {
            "statsInboundUplink": false,
            "statsInboundDownlink": false,
            "statsOutboundUplink": false,
            "statsOutboundDownlink": false
        }
    }
}
`
	fileName := "004policy.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	err := writeToFile(data, filePath)
	if err != nil {
		return err
	}
	return nil
}

func (app *XrayApp) InitDnsConfig() error {
	data := `
{
  "dns": {
    "hosts": {
      "dns.google": [
        "8.8.8.8",
        "8.8.4.4"
      ]
    },
    "servers": [
      "8.8.8.8",
      "8.8.4.4",
      {
        "address": "114.114.114.114",
        "domains": [
          "geosite:cn"
        ],
        "expectIPs": [
          "geoip:cn"
        ],
        "skipFallback": true
      },
      "localhost"
    ],
    "queryStrategy": "UseIP",
    "disableCache": false,
    "disableFallback": false,
    "disableFallbackIfMatch": false,
    "tag": "dns_tag"
  }
}
`
	fileName := "003dns.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	err := writeToFile(data, filePath)
	if err != nil {
		return err
	}
	return nil
}

func (app *XrayApp) InitLogConfig() error {
	data := `
{
  "log": {
    "access": "/tmp/log/Xray/access.log",
    "error": "/tmp/log/Xray/error.log",
    "loglevel": "debug",
    "dnsLog": true
  }
}
`
	path := "/tmp/log/Xray/"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			return err
		}
	}
	fileName := "002log.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	err := writeToFile(data, filePath)
	if err != nil {
		return err
	}
	return nil
}
func (app *XrayApp) InitApiConfig() error {
	data := `
{
  "api": {
    "tag": "api",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ]
  }
}
`
	fileName := "001api.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	err := writeToFile(data, filePath)
	if err != nil {
		return err
	}
	return nil
}

func (app *XrayApp) Subscribe(isProxy bool) error {

	subscribeUrl := app.config.SubscribeUrl
	if subscribeUrl == "" {
		return nil
	}
	proxyUrl := "http://127.0.0.1:" + strconv.Itoa(int(app.config.HttpPort))
	if !isProxy {
		proxyUrl = ""
	}
	subscribeDecodeText, err := Subscribe(subscribeUrl, proxyUrl)
	if err != nil {
		return err
	}
	subscribeDecodeText = strings.TrimSpace(subscribeDecodeText)
	lines := strings.Split(subscribeDecodeText, "\n")

	var v2rays []*V2Ray
	for _, line := range lines {
		v2rayObj, err := ParseVmessURL(line)
		if err != nil {
			return err
		}
		v2rays = append(v2rays, v2rayObj)
	}
	app.V2Rays = v2rays
	err = app.UpdateRoutingRule(v2rays)
	if err != nil {
		return err
	}

	err = app.UpdateOutbound(v2rays)
	if err != nil {
		return err
	}

	return nil

}

func (app *XrayApp) RemoveFiles(prefix string) error {
	dir := app.config.XrayConfigDir
	if dir == "" {
		dir = "."
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	// 遍历文件/目录
	for _, f := range files {
		// 检查文件名是否以给定的前缀开始
		if strings.HasPrefix(f.Name(), prefix) {
			// 构造完整的文件路径
			path := filepath.Join(dir, f.Name())
			// 删除文件
			if err := os.Remove(path); err != nil {
				log.Errorf("remove path '%v' failed,error: %v", path, err)
				continue
			}
		}
	}
	return nil
}

func (app *XrayApp) UpdateOutbound(v2rays []*V2Ray) error {

	err := app.RemoveFiles(PrefixTest)
	if err != nil {
		return err
	}

	err = app.RemoveFiles(PrefixProxy)
	if err != nil {
		return err
	}

	for _, v := range v2rays {
		err := app.V2rayToOutbound(v)
		if err != nil {
			return err
		}
	}
	return err
}

func (app *XrayApp) V2rayToOutbound(v *V2Ray) error {
	err := app.V2rayToOutboundTest(v)
	if err != nil {
		return err
	}
	err = app.V2rayToOutboundProxy(v)
	if err != nil {
		return err
	}
	return nil

}

func (app *XrayApp) V2rayToOutboundProxy(v *V2Ray) error {
	outboundProxy, err := v.TransferToOutbound("proxy_")
	if err != nil {
		return err
	}
	m := map[string]interface{}{
		"outbounds": []OutboundObject{outboundProxy},
	}
	dataProxy, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		log.Errorf("UpdateOutbound json Marshal failed, error: %v", err)
		return err
	}
	filePathProxy := filepath.Join(app.config.XrayConfigDir, PrefixProxy+outboundProxy.Tag+"_tail.json")
	err = writeToFile(string(dataProxy), filePathProxy)
	if err != nil {
		log.Errorf("UpdateOutbound write to file failed, error: %v", err)
		return err
	}
	return nil

}

func (app *XrayApp) V2rayToOutboundTest(v *V2Ray) error {
	outboundTest, err := v.TransferToOutbound("test_")
	if err != nil {
		return err
	}
	m := map[string]interface{}{
		"outbounds": []OutboundObject{outboundTest},
	}
	dataTest, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		log.Errorf("UpdateOutbound json Marshal failed, error: %v", err)
		return err
	}
	filePath := filepath.Join(app.config.XrayConfigDir, PrefixTest+outboundTest.Tag+"_tail.json")
	err = writeToFile(string(dataTest), filePath)
	if err != nil {
		log.Errorf("UpdateOutbound write to file failed, error: %v", err)
		return err
	}
	return nil

}

// UpdateRoutingRule 更新路由规则
func (app *XrayApp) UpdateRoutingRule(v2rays []*V2Ray) error {
	fileName := "006route.json"
	filePath := filepath.Join(app.config.XrayConfigDir, fileName)
	content := readFromFile(filePath)
	if content == "" {
		err := app.InitRouteConfig()
		if err != nil {
			return err
		}
		content = readFromFile(filePath)
	}
	var result map[string]interface{}

	err := json.Unmarshal([]byte(content), &result)
	if err != nil {
		return err
	}
	rules := result["routing"].(map[string]interface{})["rules"].([]interface{})

	var finalRules []map[string]interface{}
	for _, rule := range rules {

		rule1 := rule.(map[string]interface{})
		tag, ok := rule1["outboundTag"]
		if !ok || !strings.HasPrefix(tag.(string), "test_") {
			finalRules = append(finalRules, rule1)
		}
	}

	templateText := `
{
    "type": "field",
    "domain": [],
    "ip": [],
    "network": "tcp",
    "source": [],
    "user": [],
    "inboundTag": ["inbounds-test"],
    "protocol": [],
    "attrs": {
        ":method": "GET",
        "source": "{{.Source}}"
    },
    "outboundTag": "{{.Tag}}"
}
`
	t, err := template.New("rule update").Parse(templateText)
	if err != nil {
		return err
	}
	for _, v := range v2rays {
		var buf bytes.Buffer
		tag := v.GetTag("test_")
		encodeTag := url.QueryEscape(tag)
		m := map[string]string{
			"Source": encodeTag,
			"Tag":    tag,
		}
		err := t.Execute(&buf, m)
		if err != nil {
			log.Errorf("UpdateRoutingRule template execute failed,rule id: %v,error: %v", tag, err)
			continue
		}
		var r map[string]interface{}
		err = json.Unmarshal(buf.Bytes(), &r)
		if err != nil {
			log.Errorf("UpdateRoutingRule json unmarshal failed,rule id: %v,error: %v", tag, err)
			continue
		}
		finalRules = append(finalRules, r)
	}

	result["routing"].(map[string]interface{})["rules"] = finalRules

	marshal, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return err
	}
	err = writeToFile(string(marshal), filePath)
	if err != nil {
		return err
	}
	return nil

}
func (app *XrayApp) Kill() {
	locked := app.killMu.TryLock()
	if !locked {
		return
	}
	defer app.killMu.Unlock()
	if app.Process != nil {
		err := app.Process.Kill()
		if err != nil {
			log.Errorf("process kill filed %d", app.Process.Pid)
		}
	}
}
func (app *XrayApp) TimeTest() {
	go func() {
		ticker := time.NewTicker(2 * time.Hour)
		for range ticker.C {
			log.Info("TimedTest executing...")
			err := app.TestAll()
			if err != nil {
				return
			}
			app.Restart(false)
		}
	}()
}

func (app *XrayApp) Restart(withInit bool) error {

	log.Infof("restarting...")

	app.Kill()
	if !withInit {
		err := app.Run()
		if err != nil {
			return err
		}
		return nil
	} else {
		config, err := common.ReadConfig()
		if err != nil {
			return err
		}
		app.config = config.XrayConfig
		err = app.DoStart()
		if err != nil {
			return err
		}
		err = app.TestAll()
		if err != nil {
			return err
		}
		err = app.Restart(false)
		if err != nil {
			return err
		}

		return nil
	}

}

func readFromFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return ""
	}
	return string(content)
}

func writeToFile(data string, path string) error {

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(data)
	if err != nil {
		return err
	}
	return nil
}

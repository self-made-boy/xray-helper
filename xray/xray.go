package xray

import (
	"bytes"
	"encoding/json"
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

	costTimeMap := make(map[*V2Ray]int)

	var wg sync.WaitGroup
	resultCh := make(chan struct {
		v    *V2Ray
		cost int
	}, len(app.V2Rays))

	if len(app.V2Rays) != 0 {
		for _, v := range app.V2Rays {
			wg.Add(1)
			go func(v *V2Ray) {
				defer wg.Done()
				cost := app.Test(v)
				resultCh <- struct {
					v    *V2Ray
					cost int
				}{v: v, cost: cost}
			}(v)
		}
	}
	go func() {
		wg.Wait()
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
	proxyUrlStr := "http://127.0.0.1:" + strconv.Itoa(int(app.config.HttpPort))
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
	request, err := http.NewRequest("GET", "https://www.google.com", nil)
	if err != nil {
		log.Errorf("http NewRequest error %v", err)
		return -1
	}
	request.Header.Set("source", v.ID)
	now := time.Now().UnixMilli()
	response, err := client.Do(request)
	cost := time.Now().UnixMilli() - now
	if err != nil {
		log.Errorf("Id: %s call google filed  %v", v.ID, err)
		return -1
	}
	if response.StatusCode != 200 {
		log.Errorf("Id: %s StatusCode not 200  %v", v.ID, err)
		return -1
	}
	return int(cost)
}
func (app *XrayApp) Run() error {
	xrayExe := filepath.Join(app.config.XrayExeDir, "xray")
	cmd := exec.Command(xrayExe, "run", "-confdir", app.config.XrayConfigDir)
	err := cmd.Start()
	if err != nil {
		return err
	}
	app.Process = cmd.Process

	err = cmd.Wait()
	if err != nil {
		return err
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
                "inboundTag": [
                    "api"
                ],
                "outboundTag": "api"
            },
            {
                "type": "field",
                "domain": [
{{range .DomainWhitelist}}
                    "{{.}}",
{{end}}
                    "geosite:apple-cn",
                    "geosite:google-cn",
                    "geosite:cn"
                ],
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
            },
            {
                "type": "field",
                "domain": [
{{range .DomainBlacklist}}
                    "{{.}}",
{{end}}
                    "geosite:geolocation-!cn"
                ],
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
    "access": "/var/log/Xray/access.log",
    "error": "/var/log/Xray/error.log",
    "loglevel": "info",
    "dnsLog": true
  }
}
`
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
	dataProxy, err := json.Marshal(outboundProxy)
	if err != nil {
		log.Errorf("UpdateOutbound json Marshal failed, error: %v", err)
		return err
	}
	filePathProxy := filepath.Join(app.config.XrayConfigDir, PrefixProxy+v.ID+".json")
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
	dataTest, err := json.Marshal(outboundTest)
	if err != nil {
		log.Errorf("UpdateOutbound json Marshal failed, error: %v", err)
		return err
	}
	filePath := filepath.Join(app.config.XrayConfigDir, PrefixTest+v.ID+".json")
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
        "source": "{{.}}"
    },
    "outboundTag": "test_{{.}}"
}
`
	t, err := template.New("rule update").Parse(templateText)
	if err != nil {
		return err
	}
	for _, v := range v2rays {
		var buf bytes.Buffer
		err := t.Execute(&buf, v.ID)
		if err != nil {
			log.Errorf("UpdateRoutingRule template execute failed,rule id: %v,error: %v", v.ID, err)
			continue
		}
		var r map[string]interface{}
		err = json.Unmarshal(buf.Bytes(), &r)
		if err != nil {
			log.Errorf("UpdateRoutingRule json unmarshal failed,rule id: %v,error: %v", v.ID, err)
			continue
		}
		finalRules = append(finalRules, r)
	}

	result["routing"].(map[string]interface{})["rules"] = finalRules

	marshal, err := json.Marshal(result)
	if err != nil {
		return err
	}
	err = writeToFile(string(marshal), filePath)
	if err != nil {
		return err
	}
	return nil

}

func (app *XrayApp) Restart(withInit bool) error {
	if app.Process != nil {
		err := app.Process.Kill()
		if err != nil {
			log.Errorf("process kill filed %d", app.Process.Pid)
		}
	}

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

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
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

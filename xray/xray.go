package xray

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"xray-helper/common"
)

var CurrentXrayApp *XrayApp

type XrayApp struct {
	config  common.XrayConfig
	Process *os.Process
}

func NewXrayApp(config common.XrayConfig) *XrayApp {
	CurrentXrayApp = &XrayApp{config: config}
	return CurrentXrayApp
}

func (app *XrayApp) Start() error {
	err := app.InitConfig()
	if err != nil {
		return err
	}

	xrayExe := filepath.Join(app.config.XrayExeDir, "xray")
	cmd := exec.Command(xrayExe, "run", "-confdir", app.config.XrayConfigDir)
	err = cmd.Start()
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
            },
            {
                "type": "field",
                "domain": [],
                "ip": [],
                "network": "tcp",
                "source": [],
                "user": [],
                "inboundTag": ["inbounds-test"],
                "protocol": [],
                "attrs": {},
                "balancerTag": "test-balancer"
            }
        ],
        "balancers": [
            {
                "tag": "proxy-balancer",
                "selector": [
                    "proxy"
                ]
            },
            {
                "tag": "test-balancer",
                "selector": [
                    "test"
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

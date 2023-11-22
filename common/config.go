package common

import (
	"flag"
	log "github.com/golang/glog"
	"gopkg.in/yaml.v2"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	XrayConfig   XrayConfig   `json:"xrayConfig" yaml:"xrayConfig"`
	ServerConfig ServerConfig `json:"serverConfig" yaml:"serverConfig"`
}

func (c *Config) Check() error {
	err := c.ServerConfig.Check()
	if err != nil {
		return err
	}
	err = c.XrayConfig.Check()
	if err != nil {
		return err
	}
	return nil
}

type XrayConfig struct {
	Address           string   `json:"address" yaml:"address"`
	ApiPort           uint16   `json:"apiPort" yaml:"apiPort"`
	HttpPort          uint16   `json:"httpPort" yaml:"httpPort"`
	SocksPort         uint16   `json:"socksPort" yaml:"socksPort"`
	TestPort          uint16   `json:"testPort" yaml:"testPort"`
	XrayExeDir        string   `json:"xrayExeDir" yaml:"xrayExeDir"`
	XrayConfigDir     string   `json:"xrayConfigDir" yaml:"xrayConfigDir"`
	XrayAssetDir      string   `json:"xrayAssetDir" yaml:"xrayAssetDir"`
	DomainWhitelist   []string `json:"domainWhitelist" yaml:"domainWhitelist"`
	DomainBlacklist   []string `json:"domainBlacklist" yaml:"domainBlacklist"`
	SubscribeUrl      string   `json:"subscribeUrl" yaml:"subscribeUrl"`
	SubscribeRetryNum uint16   `json:"subscribeRetryNum" yaml:"subscribeRetryNum"`
}

func (c *XrayConfig) Check() error {
	if strings.TrimSpace(c.Address) == "" {
		c.Address = "127.0.0.1"
	}

	if c.SubscribeRetryNum == 0 {
		c.SubscribeRetryNum = 3
	}

	if strings.TrimSpace(c.XrayConfigDir) == "" {
		c.XrayConfigDir = "."
	}
	if strings.TrimSpace(c.Address) == "" {
		homePathStr := os.Getenv("HOME")
		defaultConfigDir := filepath.Join(homePathStr, ".config", "xray/conf")
		c.XrayConfigDir = defaultConfigDir
	}

	if strings.TrimSpace(c.XrayAssetDir) == "" {
		c.XrayAssetDir = c.XrayConfigDir
	}

	if c.ApiPort == 0 {
		c.ApiPort = 10900
	}

	if c.HttpPort == 0 {
		c.HttpPort = 10901
	}
	if c.SocksPort == 0 {
		c.SocksPort = 10902
	}

	if c.TestPort == 0 {
		c.TestPort = 10903
	}

	return nil
}

type ServerConfig struct {
	Port uint16 `json:"port" yaml:"port"`
}

func (c *ServerConfig) Check() error {

	if c.Port == 0 {
		c.Port = 20909
	}

	return nil
}

func ReadConfig() (*Config, error) {
	homePathStr, _ := os.UserHomeDir()
	defaultConfigPath := filepath.Join(homePathStr, ".config", "xray/helper.yaml")
	var configPath string
	flag.StringVar(&configPath, "config", defaultConfigPath, "config file path")

	log.Infof("config path is '%v'", configPath)
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(configPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}
	err = config.Check()
	if err != nil {
		return nil, err
	}
	return &config, nil
}

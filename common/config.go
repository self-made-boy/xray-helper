package common

import (
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	XrayConfig   XrayConfig
	ServerConfig ServerConfig
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
	Address         string   `json:"address" yaml:"address"`
	ApiPort         uint16   `json:"apiPort" yaml:"apiPort"`
	HttpPort        uint16   `json:"httpPort" yaml:"httpPort"`
	SocksPort       uint16   `json:"socksPort" yaml:"socksPort"`
	TestPort        uint16   `json:"testPort" yaml:"testPort"`
	XrayExeDir      string   `json:"xrayExeDir" yaml:"xrayExeDir"`
	XrayConfigDir   string   `json:"xrayConfigDir" yaml:"xrayConfigDir"`
	DomainWhitelist []string `json:"domainWhitelist" yaml:"domainWhitelist"`
	DomainBlacklist []string `json:"domainBlacklist" yaml:"domainBlacklist"`
}

func (c *XrayConfig) Check() error {
	if strings.TrimSpace(c.Address) == "" {
		c.Address = "127.0.0.1"
	}

	if strings.TrimSpace(c.Address) == "" {
		homePathStr := os.Getenv("HOME")
		defaultConfigDir := filepath.Join(homePathStr, ".config", "xray/conf")
		c.XrayConfigDir = defaultConfigDir
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

	return nil
}

type ServerConfig struct {
	Port              uint16 `json:"port" yaml:"port"`
	SubscribeUrl      string `json:"subscribeUrl" yaml:"subscribeUrl"`
	SubscribeRetryNum uint16 `json:"subscribeRetryNum" yaml:"subscribeRetryNum"`
}

func (c *ServerConfig) Check() error {

	if c.SubscribeRetryNum == 0 {
		c.SubscribeRetryNum = 3
	}

	if c.Port == 0 {
		c.Port = 20909
	}

	return nil
}

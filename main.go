package main

import (
	"flag"
	log "github.com/golang/glog"
	"gopkg.in/yaml.v2"
	"io"
	"os"
	"path/filepath"
	"xray-helper/common"
	"xray-helper/server"
	"xray-helper/xray"
)

func init() {
	// 开启日志输出到控制台
	flag.Set("logtostderr", "true")
}

func destroy() {

	log.Flush()
}

func main() {

	err := start()
	if err != nil {
		panic(err)
	}
	destroy()
}

func start() error {
	config, err := readConfig()
	if err != nil {
		return err
	}
	errors := make(chan error)

	go func(c chan error) {
		xrayApp := xray.NewXrayApp(config.XrayConfig)
		e := xrayApp.Start()
		if e != nil {
			c <- e
		}
	}(errors)

	go func(c chan error) {
		sv := server.NewServer(config.ServerConfig)
		e := sv.Start()
		if e != nil {
			c <- e
		}
	}(errors)

	select {
	case e := <-errors:
		return e
	}
}

func readConfig() (*common.Config, error) {
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

	var config common.Config
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

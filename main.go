package main

import (
	"flag"
	log "github.com/golang/glog"
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
	config, err := common.ReadConfig()
	if err != nil {
		return err
	}
	errors := make(chan error)

	go func(c chan<- error) {
		xrayApp := xray.NewXrayApp(config.XrayConfig)
		e := xrayApp.Start()
		if e != nil {
			c <- e
		}
	}(errors)

	go func(c chan<- error) {
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

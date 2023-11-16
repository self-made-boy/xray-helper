package server

import (
	log "github.com/golang/glog"
	"net/http"
	"strconv"
	"xray-helper/common"
)

var serverConfig common.ServerConfig

type Server struct {
	Port uint16
}

func NewServer(config common.ServerConfig) *Server {
	serverConfig = config
	return &Server{Port: config.Port}
}

func (s *Server) Start() error {
	for k, v := range routeMap {
		http.HandleFunc(k, v)
	}
	addr := ":" + strconv.FormatInt(int64(s.Port), 10)
	log.Infof("server start in %v", addr)
	err := http.ListenAndServe(addr, nil)
	return err
}

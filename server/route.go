package server

import "net/http"

var routeMap = map[string]http.HandlerFunc{
	"/addoutbound":    AddOutbound,
	"/removeoutbound": RemoveOutbound,
	"/refresh":        Refresh,
	"/restart":        ReStart,
	"/":               Root,
}

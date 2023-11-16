package server

import "net/http"

var routeMap = map[string]http.HandlerFunc{
	"/AddOutbound":    AddOutbound,
	"/RemoveOutbound": RemoveOutbound,
	"/Refresh":        Refresh,
}

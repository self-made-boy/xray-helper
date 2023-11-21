package server

import (
	"net/http"
	"xray-helper/xray"
)

func AddOutbound(w http.ResponseWriter, r *http.Request) {

}

func RemoveOutbound(w http.ResponseWriter, r *http.Request) {

}

func Refresh(w http.ResponseWriter, r *http.Request) {
	app := xray.CurrentXrayApp
	app.TestAll()
	app.Restart()
}

func ReStart(w http.ResponseWriter, r *http.Request) {

}

func Root(w http.ResponseWriter, r *http.Request) {

}

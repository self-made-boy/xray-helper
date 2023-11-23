package server

import (
	"net/http"
	"xray-helper/xray"
)

func AddOutbound(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("AddOutbound not support"))
}

func RemoveOutbound(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("RemoveOutbound not support"))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	app := xray.CurrentXrayApp
	if app == nil {
		w.Write([]byte("xray not started"))
	} else {
		w.Write([]byte("xray refresh"))
		go func() {
			app.TestAll()
			app.Restart(false)
		}()
	}

}

func ReStart(w http.ResponseWriter, r *http.Request) {
	app := xray.CurrentXrayApp

	if app == nil {
		w.Write([]byte("xray not started"))
	} else {
		w.Write([]byte("xray ReStart"))
		go func() {
			app.Restart(true)
		}()
	}

}

func Root(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("xray helper"))
}

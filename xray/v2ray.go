package xray

import (
	"fmt"
	log "github.com/golang/glog"
	jsoniter "github.com/json-iterator/go"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"xray-helper/common"
)

type V2Ray struct {
	Ps            string `json:"ps"`
	Add           string `json:"add"`
	Port          int    `json:"port"`
	ID            string `json:"id"`
	Aid           int    `json:"aid"`
	Security      string `json:"scy"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	SNI           string `json:"sni,omitempty"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	PublicKey     string `json:"pbk,omitempty"`
	ShortId       string `json:"sid,omitempty"`
	SpiderX       string `json:"spx,omitempty"`
	Flow          string `json:"flow,omitempty"`
	Alpn          string `json:"alpn,omitempty"`
	AllowInsecure bool   `json:"allowInsecure"`
	V             string `json:"v"`
	Protocol      string `json:"protocol"`
}

func (v *V2Ray) TransferToOutbound(prefix string) (OutboundObject, error) {

	tag := v.GetTag(prefix)
	core := OutboundObject{
		Tag:      tag,
		Protocol: v.Protocol,
	}
	id := v.ID
	network := v.Net
	if l := len([]byte(id)); l < 32 || l > 36 {
		id = common.StringToUUID5(id)
	}
	core.StreamSettings = StreamSettings{
		Network: network,
	}

	security := v.Security
	if security == "" {
		security = "auto"
	}
	core.Settings.Vnext = []Vnext{
		{
			Address: v.Add,
			Port:    v.Port,
			Users: []User{
				{
					ID:         id,
					AlterID:    v.Aid,
					Security:   security,
					Encryption: "none",
				},
			},
		},
	}

	switch strings.ToLower(v.Net) {
	case "grpc":
		if v.Path == "" {
			v.Path = "GunService"
		}
		core.StreamSettings.GrpcSettings = &GrpcSettings{ServiceName: v.Path}
	case "ws":
		core.StreamSettings.WsSettings = &WsSettings{
			Path: v.Path,
			Headers: Headers{
				Host: v.Host,
			},
		}
	case "mkcp", "kcp":
		core.StreamSettings.KcpSettings = &KcpSettings{
			Mtu:              1350,
			Tti:              50,
			UplinkCapacity:   12,
			DownlinkCapacity: 100,
			Congestion:       false,
			ReadBufferSize:   2,
			WriteBufferSize:  2,
			Header: KcpHeader{
				Type: v.Type,
			},
			Seed: v.Path,
		}
	case "tcp":
		if strings.ToLower(v.Type) == "http" {
			tcpSetting := TCPSettings{
				ConnectionReuse: true,
				Header: TCPHeader{
					Type: "http",
					Request: HTTPRequest{
						Version: "1.1",
						Method:  "GET",
						Path:    strings.Split(v.Path, ","),
						Headers: HTTPReqHeader{
							Host: strings.Split(v.Host, ","),
							UserAgent: []string{
								"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36",
								"Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46",
							},
							AcceptEncoding: []string{"gzip, deflate"},
							Connection:     []string{"keep-alive"},
							Pragma:         "no-cache",
						},
					},
					Response: HTTPResponse{
						Version: "1.1",
						Status:  "200",
						Reason:  "OK",
						Headers: HTTPRespHeader{
							ContentType:      []string{"application/octet-stream", "video/mpeg"},
							TransferEncoding: []string{"chunked"},
							Connection:       []string{"keep-alive"},
							Pragma:           "no-cache",
						},
					},
				},
			}
			tcpSetting.Header.Request.Headers.Host = strings.Split(v.Host, ",")
			if v.Path != "" {
				tcpSetting.Header.Request.Path = strings.Split(v.Path, ",")
				for i := range tcpSetting.Header.Request.Path {
					if !strings.HasPrefix(tcpSetting.Header.Request.Path[i], "/") {
						tcpSetting.Header.Request.Path[i] = "/" + tcpSetting.Header.Request.Path[i]
					}
				}
			}
			core.StreamSettings.TCPSettings = &tcpSetting
		}
	case "h2", "http":
		if v.Host != "" {
			core.StreamSettings.HTTPSettings = &HttpSettings{
				Path: v.Path,
				Host: strings.Split(v.Host, ","),
			}
		} else {
			core.StreamSettings.HTTPSettings = &HttpSettings{
				Path: v.Path,
			}
		}
	default:
		return core, fmt.Errorf("unexpected transport type: %v", v.Net)
	}
	if strings.ToLower(v.TLS) == "tls" {
		core.StreamSettings.Security = "tls"
		core.StreamSettings.TLSSettings = &TLSSettings{}
		if v.AllowInsecure {
			core.StreamSettings.TLSSettings.AllowInsecure = true
		}
		// SNI
		if v.SNI != "" {
			core.StreamSettings.TLSSettings.ServerName = v.SNI
		} else if v.Host != "" {
			core.StreamSettings.TLSSettings.ServerName = v.Host
		}
		// Alpn
		if v.Alpn != "" {
			alpn := strings.Split(v.Alpn, ",")
			for i := range alpn {
				alpn[i] = strings.TrimSpace(alpn[i])
			}
			core.StreamSettings.TLSSettings.Alpn = alpn
		}
		// uTLS fingerprint
		core.StreamSettings.TLSSettings.Fingerprint = v.Fingerprint
	} else if strings.ToLower(v.TLS) == "xtls" {
		core.StreamSettings.Security = "xtls"
		core.StreamSettings.XTLSSettings = &TLSSettings{}
		// SNI
		if v.SNI != "" {
			core.StreamSettings.XTLSSettings.ServerName = v.SNI
		} else if v.Host != "" {
			core.StreamSettings.XTLSSettings.ServerName = v.Host
		}
		if v.AllowInsecure {
			core.StreamSettings.XTLSSettings.AllowInsecure = true
		}
		if v.Alpn != "" {
			alpn := strings.Split(v.Alpn, ",")
			for i := range alpn {
				alpn[i] = strings.TrimSpace(alpn[i])
			}
			core.StreamSettings.XTLSSettings.Alpn = alpn
		}
	} else if strings.ToLower(v.TLS) == "reality" {
		core.StreamSettings.Security = "reality"
		core.StreamSettings.RealitySettings = &RealitySettings{
			ServerName:  v.SNI,
			Fingerprint: v.Fingerprint,
			Show:        false,
			PublicKey:   v.PublicKey,
			ShortID:     v.ShortId,
			SpiderX:     v.SpiderX,
		}
	}
	// Flow
	if v.Flow != "" {
		vnext := core.Settings.Vnext.([]Vnext)
		vnext[0].Users[0].Flow = v.Flow
		core.Settings.Vnext = vnext
	}

	return core, nil

}

func (v *V2Ray) GetTag(prefix string) string {
	tag := prefix + "-" + v.Ps
	tag = strings.ReplaceAll(tag, " ", "")
	tag = strings.ReplaceAll(tag, "：", "")
	tag = strings.ReplaceAll(tag, "·", "")
	tag = strings.ReplaceAll(tag, "\\", "")
	tag = strings.ReplaceAll(tag, "/", "")
	tag = strings.ReplaceAll(tag, ":", "")
	tag = strings.ReplaceAll(tag, "*", "")
	tag = strings.ReplaceAll(tag, "?", "")
	tag = strings.ReplaceAll(tag, "\"", "")
	tag = strings.ReplaceAll(tag, "'", "")
	tag = strings.ReplaceAll(tag, ">", "")
	tag = strings.ReplaceAll(tag, "<", "")
	tag = strings.ReplaceAll(tag, "|", "")

	return tag
}

func ParseVmessURL(vmess string) (data *V2Ray, err error) {
	var info V2Ray
	s2 := vmess[8:]
	// perform base64 decoding and unmarshal to VmessInfo
	raw, err := common.Base64StdDecode(s2)
	if err != nil {
		raw, err = common.Base64URLDecode(vmess[8:])
	}
	if err != nil {
		// not in json format, try to resolve as vmess://BASE64(Security:ID@Add:Port)?remarks=Ps&obfsParam=Host&Path=Path&obfs=Net&tls=TLS
		var u *url.URL
		u, err = url.Parse(vmess)
		if err != nil {
			return
		}
		re := regexp.MustCompile(`.*:(.+)@(.+):(\d+)`)
		s := strings.Split(vmess[8:], "?")[0]
		s, err = common.Base64StdDecode(s)
		if err != nil {
			s, _ = common.Base64URLDecode(s)
		}
		subMatch := re.FindStringSubmatch(s)
		if subMatch == nil {
			err = fmt.Errorf("unrecognized vmess address")
			return
		}
		q := u.Query()
		ps := q.Get("remarks")
		if ps == "" {
			ps = q.Get("remark")
		}
		obfs := q.Get("obfs")
		obfsParam := q.Get("obfsParam")
		path := q.Get("path")
		if obfs == "kcp" || obfs == "mkcp" {
			m := make(map[string]string)
			//cater to v2rayN definition
			_ = jsoniter.Unmarshal([]byte(obfsParam), &m)
			path = m["seed"]
			obfsParam = ""
		}
		aid := q.Get("alterId")
		if aid == "" {
			aid = q.Get("aid")
		}
		var aidNum int64
		if aid != "" {
			aidNum, err = strconv.ParseInt(aid, 10, 64)
			if err != nil {
				err = fmt.Errorf("unrecognized aid")
				return
			}
		}
		security := q.Get("scy")
		if security == "" {
			security = q.Get("security")
		}
		sni := q.Get("sni")
		port, err := strconv.ParseInt(subMatch[3], 10, 64)
		if err != nil {
			err = fmt.Errorf("unrecognized port")
			return nil, err
		}
		info = V2Ray{
			ID:            subMatch[1],
			Add:           subMatch[2],
			Port:          int(port),
			Ps:            ps,
			Host:          obfsParam,
			Path:          path,
			SNI:           sni,
			Net:           obfs,
			Aid:           int(aidNum),
			Security:      security,
			TLS:           map[string]string{"1": "tls"}[q.Get("tls")],
			AllowInsecure: false,
		}
		if info.Net == "websocket" {
			info.Net = "ws"
		}
	} else {
		// fuzzily parse allowInsecure
		if allowInsecure := gjson.Get(raw, "allowInsecure"); allowInsecure.Exists() {
			if newRaw, err := sjson.Set(raw, "allowInsecure", allowInsecure.Bool()); err == nil {
				raw = newRaw
			}
		}
		err = jsoniter.Unmarshal([]byte(raw), &info)
		if err != nil {
			return
		}
	}
	// correct the wrong vmess as much as possible
	if strings.HasPrefix(info.Host, "/") && info.Path == "" {
		info.Path = info.Host
		info.Host = ""
	}

	info.Protocol = "vmess"
	return &info, nil
}

func Subscribe(subscribeUrl string, proxyUrl string) (string, error) {
	log.Infof("Subscribe starting '%s' with proxy '%s'", subscribeUrl, proxyUrl)
	var client *http.Client
	if len(strings.TrimSpace(proxyUrl)) == 0 {
		client = http.DefaultClient
	} else {

		proxyUrl, _ := url.Parse(proxyUrl)

		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		}

		client = &http.Client{
			Transport: transport,
		}
	}

	response, err := client.Get(subscribeUrl)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	text, err := common.Base64StdDecode(string(body))
	if err != nil {
		return "", err
	}
	log.Infof("Subscribe starting '%s' with proxy '%s'; get result '%s'", subscribeUrl, proxyUrl, text)
	return text, nil
}

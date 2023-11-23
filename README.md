
usage
```shell
make clean
make release
docker build -t xray-helper:1.0 build/.

docker run \
-p 10901:10901 \
-p 10902:10902 \
-p 20909:20909 \
-v ~/.config/xray:/root/app/xray/helper/conf/ \
-d xray-helper:1.0 -config=/root/app/xray/helper/conf/helper.yaml


```

window
```shell
set GOOS=linux
set GOARCH=amd64 
go build -ldflags "-s -w" -o build/xray-helper

docker run `
-p 10901:10901 `
-p 10902:10902 `
-p 20909:20909 `
-v c:/Users/xx/.config/xray:/root/app/xray/helper/conf `
-d xray-helper:1.0 "-config=/root/app/xray/helper/conf/helper.yaml"

```

log dir
```shell
/tmp/log/Xray/
```
config example

```yaml
xrayConfig:
  address: 127.0.0.1
  apiPort: 10900
  httpPort: 10901
  socksPort: 10902
  testPort: 10903
  xrayExeDir: /root/app/xray
  xrayConfigDir: /root/app/xray/conf
  xrayAssetDir: /root/app/xray/share
  domainWhitelist:
    - baidu.com
  DomainBlacklist:
    - google.com
  subscribeUrl: https://xxxx/link/xxx
  subscribeRetryNum: 3
serverConfig:
  port: 20909
```

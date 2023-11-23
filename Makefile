.PHONY: clean release image docker

clean:
	rm -f build/xray-helper
release:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o build/xray-helper
docker:
	docker build -t xray-helper build/.
image: clean release docker
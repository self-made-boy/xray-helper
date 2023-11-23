FROM alpine:latest
RUN /bin/sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update
RUN apk add --no-cache curl
RUN apk add --no-cache busybox-extras

RUN mkdir -p /root/app/xray/share
RUN mkdir -p /root/app/xray/conf
RUN mkdir -p /root/app/xray/helper

COPY xray/xray /root/app/xray/
COPY xray/*.dat /root/app/xray/share/
COPY config.yaml /root/app/xray/helper/
COPY xray-helper /root/app/xray/helper/

ENTRYPOINT ["/root/app/xray/helper/xray-helper"]
CMD ["-config=/root/app/xray/helper/config.yaml"]

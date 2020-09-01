FROM haproxytech/haproxy-alpine:2.0

RUN apk add luarocks5.3 curl gcc libc-dev lua5.3-dev openssl-dev && \
    luarocks-5.3 install luaossl

COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg

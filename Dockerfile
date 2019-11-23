FROM alpine:3

RUN adduser -D -g '' app app

COPY scannercli /usr/local/bin/scannercli
COPY scanner-adapter /usr/local/bin/scanner-adapter

ENTRYPOINT ["scanner-adapter"]

FROM alpine:3.14

RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories

RUN apk update \
    && apk upgrade musl \
    && apk add ca-certificates dpkg@edge rpm@edge expat@edge libbz2@edge libarchive@edge db@edge

RUN adduser -u 1000 -D -g '' scanner scanner

COPY scanner-adapter /usr/local/bin/scanner-adapter

USER scanner

ENTRYPOINT ["scanner-adapter"]

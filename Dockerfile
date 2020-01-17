FROM alpine:3

RUN apk add --no-cache ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/cache/apk/*

RUN adduser -u 1000 -D -g '' scanner scanner

COPY scanner-adapter /usr/local/bin/scanner-adapter

USER scanner

ENTRYPOINT ["scanner-adapter"]

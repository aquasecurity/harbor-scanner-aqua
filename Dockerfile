FROM alpine:3

RUN adduser -D -g '' app app

COPY scanner-adapter /usr/local/bin/scanner-adapter

USER app

ENTRYPOINT ["scanner-adapter"]

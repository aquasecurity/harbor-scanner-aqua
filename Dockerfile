FROM alpine:3

RUN adduser -u 1000 -D -g '' scanner scanner

COPY scanner-adapter /usr/local/bin/scanner-adapter

USER scanner

ENTRYPOINT ["scanner-adapter"]

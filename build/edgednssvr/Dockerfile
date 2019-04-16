FROM alpine:latest
ENV DNS_FWDR=""
WORKDIR /home
COPY ./edgednssvr .
ENTRYPOINT ./edgednssvr -port=53 -fwdr=$DNS_FWDR

FROM alpine:latest

ADD webhook-example /webhook-example
ENTRYPOINT ["./webhook-example"]
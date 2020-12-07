FROM golang:alpine
WORKDIR /apps/
ADD . .
RUN GOBIN=/apps/bin/ GOOS=linux GOARCH=amd64 go install -a -mod vendor -trimpath -ldflags='-w -s' ./cmd/...

FROM alpine
WORKDIR /apps/
RUN apk add --no-cache ca-certificates tzdata
COPY --from=0 /apps/bin/ /apps/

ENTRYPOINT ["/apps/metrics-collector"]

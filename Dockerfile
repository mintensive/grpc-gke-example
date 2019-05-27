#################################################
# STEP 1 build cache with Go modules cache
#################################################
FROM golang:1.11.5-alpine3.9 AS builder_cache
RUN apk update && apk add --no-cache git mercurial make build-base
WORKDIR /go/src/github.com/mintenstive/grpc-gke-example
ENV GO111MODULE=on
COPY go.mod .
COPY go.sum .
# "go mod download" downloads dependencies only when something changes in the go.mod or go.sum file
# which are cached via Docker's layer.
RUN go mod download

#################################################
# STEP 2 build the server
#################################################
FROM builder_cache AS builder
RUN apk update && apk add --no-cache git mercurial make build-base
WORKDIR /go/src/github.com/mintenstive/grpc-gke-example
ADD . .
# build the server
RUN CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o grpc-gke-example

#################################################
# STEP 3 TLS certificates from the latest image
#################################################
FROM alpine:latest AS certs
RUN apk update && apk add --no-cache git ca-certificates && update-ca-certificates

#################################################
# STEP 4 build a small image
#################################################
FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/src/github.com/mintenstive/grpc-gke-example/grpc-gke-example /

# Run the server as a non-root user.
# We use just a "random" PID without a username and group because our server does not need them.
USER 10001

EXPOSE 8443 50052
ENTRYPOINT ["/grpc-gke-example"]

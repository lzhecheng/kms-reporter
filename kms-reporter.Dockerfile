FROM mcr.microsoft.com/oss/go/microsoft/golang:1.24.5 AS builder
ARG ENABLE_GIT_COMMAND=true
ARG ARCH=amd64

WORKDIR /app
COPY . .
RUN go build -o /app/kms-reporter cmd/reporter.go

FROM mcr.microsoft.com/mirror/docker/library/alpine:3.16
RUN apk add libc6-compat
COPY --from=builder /app/kms-reporter /usr/local/bin/kms-reporter

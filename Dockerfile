FROM golang:1.25.11-alpine3.23@sha256:60e626bbde32def8694687d03536ea4341b19e5f068e9a630225a1dfbd0505c9 AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/RamazanKara/kube-shield/pkg/version.Version=${VERSION} -X github.com/RamazanKara/kube-shield/pkg/version.Commit=${COMMIT} -X github.com/RamazanKara/kube-shield/pkg/version.Date=${DATE}" -o /kube-shield .

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -u 1000 kubeshield
USER kubeshield

COPY --from=builder /kube-shield /usr/local/bin/kube-shield

ENTRYPOINT ["kube-shield"]
CMD ["scan"]

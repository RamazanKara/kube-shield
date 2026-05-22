FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/RamazanKara/kube-shield/pkg/version.Version=${VERSION} -X github.com/RamazanKara/kube-shield/pkg/version.Commit=${COMMIT} -X github.com/RamazanKara/kube-shield/pkg/version.Date=${DATE}" -o /kube-shield .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -u 1000 kubeshield
USER kubeshield

COPY --from=builder /kube-shield /usr/local/bin/kube-shield

ENTRYPOINT ["kube-shield"]
CMD ["scan"]

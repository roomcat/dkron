FROM golang:1.13 as build-dkron
LABEL maintainer="Victor Castell <victor@victorcastell.com>"

RUN mkdir -p /app
WORKDIR /app

ENV GOPROXY=https://goproxy.cn
ENV GO111MODULE=on
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .
RUN go install ./...

FROM alpine

RUN set -x \
	&& buildDeps='bash ca-certificates openssl tzdata' \
	&& apk add --update $buildDeps \
	&& rm -rf /var/cache/apk/* \
	&& mkdir -p /opt/local/dkron

EXPOSE 8080 8946

ENV SHELL /bin/bash
WORKDIR /opt/local/dkron

COPY --from=build-dkron /go/bin/dkron .
COPY --from=build-dkron /go/bin/dkron-* ./
ENTRYPOINT ["/opt/local/dkron/dkron"]

CMD ["--help"]

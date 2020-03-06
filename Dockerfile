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
	&& buildDeps='ca-certificates' \
	&& apk add --update $buildDeps \
	&& rm -rf /var/cache/apk/*

EXPOSE 8080 8946

COPY --from=build-dkron /go/bin/dkron /bin/dkron
COPY --from=build-dkron /go/bin/dkron-executor-http /bin/dkron-executor-http
COPY --from=build-dkron /go/bin/dkron-executor-shell /bin/dkron-executor-shell

ENTRYPOINT ["/bin/dkron"]

CMD ["--help"]

FROM golang:1.13-alpine as build-dkron
LABEL maintainer="Victor Castell <victor@victorcastell.com>"

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
	apk add --no-cache git gcc libc-dev

RUN mkdir -p /app
WORKDIR /app

ENV GOPROXY=https://goproxy.cn
# ENV GO111MODULE=on
# COPY go.mod go.mod
# COPY go.sum go.sum
# RUN go mod download

COPY . .
# RUN go install ./...
RUN go build -o /bin/dkron

FROM alpine

RUN set -x \
	&& buildDeps='ca-certificates' \
	&& apk add --update $buildDeps \
	&& rm -rf /var/cache/apk/*

EXPOSE 8080 8946

COPY --from=build-dkron /bin/dkron /bin/dkron
# COPY --from=build-dkron /go/bin/dkron-executor-http /bin/dkron-executor-http
# COPY --from=build-dkron /go/bin/dkron-executor-shell /bin/dkron-executor-shell

ENTRYPOINT ["/bin/dkron"]

CMD ["--help"]

# LAYER: BASE
FROM golang:1.13.5-alpine3.11 AS build_base_golang

LABEL maintainer="lee@geeksinthewoods.com"

RUN apk --no-cache add \
            git build-base gcc

# Change dir to project base.
WORKDIR /project/build

# Install fresh for auto-reloads for dev when running docker-compose.
RUN go get github.com/pilu/fresh

# Enable go modules.
#ARG GOPROXY=https://goproxy.io
#ENV GOPROXY=$GOPROXY
ENV GO111MODULE="on"
COPY go.mod .
COPY go.sum .
RUN go mod download

RUN echo $GOPATH

# LAYER: DEV - All the project go files.
FROM build_base_golang AS dev

ARG name
ARG code_path=./examples/${name}
ARG commit_ref=-

# Copy shared packages.
COPY internal ./internal
COPY pkg ./pkg

# Copy cmd specific packages.
COPY ${code_path} ${code_path}

# Copy the global templates.
ADD configs/fresh-auto-reload.conf /runner.conf

WORKDIR ${code_path}

ADD ${code_path}/static /static
ENV STATIC_DIR=/static

ADD ${code_path}/templates /templates
ENV TEMPLATE_DIR=/templates

ENTRYPOINT ["fresh", "-c", "/runner.conf"]



# LAYER: TESTER - Run all the unittets for the project.
#   * Seperate layer so can target only this layer to be executed.
FROM dev AS tester

# Run the tests for the service being built.
RUN go test -v ./...



# LAYER: BUILDER - Do the golang build to produce a static binary.
#   * Seperate layer so can target only this layer to be executed.
FROM dev AS builder

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.build=${commit_ref}" -a -installsuffix nocgo -o /gosrv .



# FINAL LAYER - Entrypoint for the docker container image.
FROM alpine:3.11

RUN apk --update --no-cache add \
            tzdata ca-certificates curl openssl

COPY --from=builder /gosrv /

COPY --from=dev /static /static
ENV STATIC_DIR=/static

COPY --from=dev /templates /templates
ENV TEMPLATE_DIR=/templates

ARG name
ENV SERVICE_NAME $name

ARG env="dev"
ENV ENV $env

ARG gogc="20"
ENV GOGC $gogc

ENTRYPOINT ["/gosrv"]

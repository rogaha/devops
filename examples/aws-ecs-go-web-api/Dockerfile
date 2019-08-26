# LAYER: BASE
FROM golang:1.12.9-alpine3.9 AS dev

LABEL maintainer="lee@geeksinthewoods.com"

RUN apk --no-cache add \
            git build-base gcc

# Change dir to project base.
WORKDIR /project/build

# Enable go modules.
ENV GO111MODULE="on"
COPY go.mod .
COPY go.sum .
COPY vendor ./vendor
RUN go mod vendor
RUN go get github.com/pilu/fresh



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
FROM dev AS tester



# Run the tests for the service being built.
RUN go test -mod=/project/build/vendor -v ./...



# LAYER: BUILDER - Do the golang build to produce a static binary.
FROM dev AS builder

RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -ldflags "-X main.build=${commit_ref}" -a -installsuffix nocgo -o /gosrv .



# LAYER: Lambda: Support deploying this service to AWS Lambda with an API gateway.
FROM lambci/lambda:go1.x AS lambda

COPY --from=builder /gosrv /var/task/gosrv
COPY --from=dev /static /var/task/static
COPY --from=dev /templates /var/task/templates

WORKDIR /var/task


# FINAL LAYER - Entrypoint for the docker container image.
FROM alpine:3.9

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

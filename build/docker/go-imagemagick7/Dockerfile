FROM golang:1.13.5-alpine3.11 AS builder

LABEL maintainer="lee@geeksinthewoods.com"

RUN apk --update --no-cache add \
            ghostscript-dev ghostscript \
			imagemagick-dev imagemagick

COPY build/docker/go-imagemagick7/ImageMagick-7-policy.xml /var/task/imagemagick/etc/ImageMagick-7/policy.xml
RUN cat /var/task/imagemagick/etc/ImageMagick-7/policy.xml

# Change dir to project base.
WORKDIR /project/build

# Enable go modules.
ARG GOPROXY=https://goproxy.io
ENV GOPROXY=$GOPROXY
ENV GO111MODULE="on"
COPY go.mod .
COPY go.sum .
RUN go mod download

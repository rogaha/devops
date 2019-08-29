# LAYER: BASE
FROM build/docker/go-imagemagic7 AS build_base_golang

LABEL maintainer="lee@geeksinthewoods.com"

# Change dir to project base.
WORKDIR /project/build

# Copy shared packages.
COPY internal ./internal
COPY pkg ./pkg

# ... the rest of your docker file for the specfic service ...
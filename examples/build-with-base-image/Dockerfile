# LAYER: BASE
FROM build/docker/go-imagemagic7 AS build_example_base

LABEL maintainer="lee@geeksinthewoods.com"

# Change dir to project base.
WORKDIR /project/build

# Copy shared packages.
COPY internal ./internal
COPY pkg ./pkg

# ... the rest of your docker file for the specfic service ...
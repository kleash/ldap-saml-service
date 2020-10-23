FROM golang:1.13-stretch AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=1

WORKDIR /build

# Let's cache modules retrieval - those don't change so often
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code necessary to build the application
# You may want to change this to copy only what you actually need.
COPY . .

# Build the application
RUN go build -o ./auth-server

# Let's create a /dist folder containing just the files necessary for runtime.
# Later, it will be copied as the / (root) of the output image.
WORKDIR /dist
RUN cp /build/auth-server ./auth-server
RUN mkdir -p /log

# Create the minimal runtime image
FROM alpine
RUN apk --no-cache add ca-certificates
COPY --from=builder /dist /

ENTRYPOINT ["/auth-server"]

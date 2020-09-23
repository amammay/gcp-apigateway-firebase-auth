FROM golang:1.15-alpine as builder

WORKDIR /src/gateway

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
# Expecting to copy go.mod and if present go.sum.
COPY go.* ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

# Build the binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o /server ./cmd/

FROM gcr.io/distroless/base

USER nobody:nobody

COPY --from=builder /server /server

ENTRYPOINT ["/server"]

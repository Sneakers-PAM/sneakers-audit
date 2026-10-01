# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.5
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/audit ./cmd/audit

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/audit /audit
COPY --from=build /src/migrations /migrations
ENV MIGRATIONS_DIR=/migrations
USER nonroot:nonroot
ENTRYPOINT ["/audit"]

FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY collectors ./collectors
RUN CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -buildvcs=false -o /console ./cmd/console
FROM scratch
COPY --from=build /console /console
USER 65532:65532
ENTRYPOINT ["/console"]

# Historical synthetic demo only; pilot requires private state and a native build.
CMD ["--demo"]

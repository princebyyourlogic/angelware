FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/angelware ./cmd/angelware

FROM scratch
COPY --from=build /out/angelware /angelware
USER 65534:65534
EXPOSE 3074/tcp 3074/udp 3075/udp
ENTRYPOINT ["/angelware"]

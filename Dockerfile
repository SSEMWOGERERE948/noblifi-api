FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/noblifi-api ./cmd/server

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/noblifi-api /app/noblifi-api
EXPOSE 8080
CMD ["/app/noblifi-api"]


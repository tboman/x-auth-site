# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/service ./services/risk-service/cmd

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/service /service
ENV PORT=8081
EXPOSE 8081
USER nonroot:nonroot
ENTRYPOINT ["/service"]

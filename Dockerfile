FROM golang:1.21.1-alpine AS base

WORKDIR /usr/src/app


FROM base AS copy-stage

COPY . /usr/src/app/simple-micro-auth


FROM copy-stage AS build-stage

WORKDIR /usr/src/app/simple-micro-auth

RUN go build ./src/main.go


FROM alpine:3.18 AS copy-build-stage

COPY --from=build-stage /usr/src/app/simple-micro-auth/main /usr/src/app/simple-micro-auth/main


FROM copy-build-stage AS run-stage

WORKDIR /usr/src/app/simple-micro-auth

CMD [ "./main" ]
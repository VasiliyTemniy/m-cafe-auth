.PHONY: proto, build
proto:
	protoc --go_out=./src --go_opt=paths=source_relative --go-grpc_out=./src --go-grpc_opt=paths=source_relative proto/auth.proto

build:
	go build ./src/main.go

test:
	go test ./src/tests

run:
	go run ./src/main.go

docker-image:
	docker build -t simple-micro-auth .

docker-compose:
	docker-compose up -d
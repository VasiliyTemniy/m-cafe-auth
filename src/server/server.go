package server

import (
	"fmt"
	"log"
	"net"

	"simple-micro-auth/src/cert"
	"simple-micro-auth/src/configs"
	pb "simple-micro-auth/src/proto"
	"simple-micro-auth/src/services"

	"google.golang.org/grpc"
)

var grpcServer *grpc.Server

// STEPS!
// 1. DONE! Make it work the same but with UUIDs instead of ints
// 2. Add ORM (gorm)
// 3. Add HTTP GIN server as option
// 4. Make it accept connections from docker network only
// 5. Introduce the mTLS to secure the connection
// 6. Make something like api keys to access the server from different services

func RunServer() {

	cert.ReadCertificates("token")

	var host string

	if configs.EnvDockerized == "true" {
		host = "0.0.0.0"
	} else {
		host = "127.0.0.1"
	}

	listenPort := fmt.Sprintf("%s:%s", host, configs.EnvPort)

	lis, err := net.Listen("tcp", listenPort)

	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	} else {
		fmt.Println("Listening on " + listenPort)
	}

	grpcServer := grpc.NewServer()
	service := &services.AuthServiceServer{}

	pb.RegisterAuthServiceServer(grpcServer, service)
	err = grpcServer.Serve(lis)

	if err != nil {
		log.Fatalf("Error strating server: %v", err)
	}
}

func StopServer() {
	grpcServer.Stop()
}

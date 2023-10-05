package server

import (
	"fmt"
	"log"
	"net"

	"simple-micro-auth/src/configs"
	pb "simple-micro-auth/src/proto"
	"simple-micro-auth/src/services"

	"google.golang.org/grpc"
)

var grpcServer *grpc.Server

func RunServer() {
	listenPort := fmt.Sprintf("127.0.0.1:%s", configs.EnvPort)

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

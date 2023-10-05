package server

import (
	"fmt"
	"log"
	"net"

	"m-cafe-auth/src/configs"
	pb "m-cafe-auth/src/proto"
	"m-cafe-auth/src/services"

	"google.golang.org/grpc"
)

var grpcServer *grpc.Server

func RunServer() {
	listenPort := fmt.Sprintf("[::1]:%s", configs.EnvPort)

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

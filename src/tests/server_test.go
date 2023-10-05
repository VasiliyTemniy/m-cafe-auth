package tests

import (
	"context"
	"fmt"
	"simple-micro-auth/src/server"
	"testing"

	pb "simple-micro-auth/src/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestMain(t *testing.T) {
	flushDB()

	// Run server in background
	go func() {
		server.RunServer()
	}()

	// Send gRPC message to that server
	conn, err := grpc.Dial("[::1]:4006", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}

	defer conn.Close()

	// Create gRPC client
	client := pb.NewAuthServiceClient(conn)

	// Create request
	req := &pb.AuthRequest{
		Id:         123,
		LookupHash: "test",
		Password:   "test",
	}

	// Send request
	res, err := client.CreateAuth(context.Background(), req)
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	if res.Id != 123 {
		t.Errorf("expected id: %s, got: %s", "123", fmt.Sprintf("%v", (res.Id)))
	}
}

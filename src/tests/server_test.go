package tests

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"simple-micro-auth/src/cert"
	"simple-micro-auth/src/configs"
	"simple-micro-auth/src/server"
	"testing"
	"time"

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

	time.Sleep(1 * time.Second)

	var host string

	if configs.EnvDockerized == "true" {
		host = "0.0.0.0"
	} else {
		host = "127.0.0.1"
	}

	listenPort := fmt.Sprintf("%s:%s", host, configs.EnvPort)

	// Send gRPC message to that server
	conn, err := grpc.Dial(listenPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	authRes, err := client.CreateAuth(context.Background(), req)
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	if authRes.Id != 123 {
		t.Errorf("expected id: %s, got: %s", "123", fmt.Sprintf("%v", (authRes.Id)))
	}

	// Test RSA PublicKey sending
	publicKeyRes, err := client.GetPublicKey(context.Background(), &pb.PublicKeyRequest{Target: "token"})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	expectedPublicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("could not convert public key: %v", err)
	}

	if !bytes.Equal(expectedPublicKeyBytes, publicKeyRes.PublicKey) {
		t.Errorf("expected public key: %s, got: %s", expectedPublicKeyBytes, publicKeyRes.PublicKey)
	}
}

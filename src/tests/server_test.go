package tests

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"simple-micro-auth/src/cert"
	c "simple-micro-auth/src/configs"
	"simple-micro-auth/src/server"
	"testing"
	"time"

	pb "simple-micro-auth/src/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestMain(t *testing.T) {
	db.FlushDB()

	// Run server in background
	go func() {
		server.RunServer()
	}()

	time.Sleep(1 * time.Second)

	var host string

	if c.EnvDockerized == "true" {
		host = "0.0.0.0"
	} else {
		host = "127.0.0.1"
	}

	listenPort := fmt.Sprintf("%s:%s", host, c.EnvPort)

	// Test 1: Create gRPC connection
	conn, err := grpc.Dial(listenPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}

	defer conn.Close()

	client := pb.NewAuthServiceClient(conn)

	// Test 2: Create request
	newAuthReq := &pb.AuthRequest{
		UserId:   userId,
		AppId:    appId,
		Password: password,
	}

	authRes, err := client.CreateAuth(context.Background(), newAuthReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if authRes.UserId != userId {
		t.Errorf("expected id: %s, got: %s", "test-user", fmt.Sprintf("%v", authRes.UserId))
	}

	if authRes.Token == "" {
		t.Errorf("expected token: %s, got: %s", "token", authRes.Token)
	}

	// Test 3: Update request
	updateAuthReq := &pb.UpdateAuthRequest{
		UserId:      userId,
		AppId:       appId,
		OldPassword: password,
		NewPassword: password + "1",
	}

	updAuthRes, err := client.UpdateAuth(context.Background(), updateAuthReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if updAuthRes.UserId != userId {
		t.Errorf("expected id: %s, got: %s", "test-user", fmt.Sprintf("%v", updAuthRes.UserId))
	}

	if updAuthRes.Token == "" {
		t.Errorf("expected token: %s, got: %s", "token", updAuthRes.Token)
	}

	// Test 4: Verify request
	correctCredentials := &pb.CredentialsRequest{
		UserId:   userId,
		AppId:    appId,
		Password: password + "1",
	}

	verifyRes, err := client.VerifyCredentials(context.Background(), correctCredentials)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !verifyRes.Success {
		t.Errorf("expected success: %v, got: %v", true, verifyRes.Success)
	}

	if verifyRes.Error != "" {
		t.Errorf("expected error: %s, got: %s", "", verifyRes.Error)
	}

	incorrectCredentials := &pb.CredentialsRequest{
		UserId:   userId,
		AppId:    appId,
		Password: password + "2",
	}

	verifyRes, err = client.VerifyCredentials(context.Background(), incorrectCredentials)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if verifyRes.Success {
		t.Errorf("expected success: %v, got: %v", false, verifyRes.Success)
	}

	if verifyRes.Error == "" {
		t.Errorf("expected error: %s, got: %s", "something", verifyRes.Error)
	}

	// Test 5: Grant auth
	grantAuthReq := &pb.AuthRequest{
		UserId:   userId,
		AppId:    appId,
		Password: password + "1",
	}

	grantAuthRes, err := client.GrantAuth(context.Background(), grantAuthReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if grantAuthRes.UserId != userId {
		t.Errorf("expected id: %s, got: %s", "test-user", fmt.Sprintf("%v", grantAuthRes.UserId))
	}

	if grantAuthRes.Token == "" {
		t.Errorf("expected token: %s, got: %s", "token", grantAuthRes.Token)
	}

	// Test 6: Refresh token
	refreshTokenReq := &pb.RefreshTokenRequest{
		Token: grantAuthRes.Token,
		Ttl:   "10s",
	}

	refreshTokenRes, err := client.RefreshToken(context.Background(), refreshTokenReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if refreshTokenRes.UserId != grantAuthRes.UserId {
		t.Errorf("expected id: %s, got: %s", grantAuthRes.UserId, refreshTokenRes.UserId)
	}

	if refreshTokenRes.Token == "" {
		t.Errorf("expected token: %s, got: %s", "token", refreshTokenRes.Token)
	}

	if refreshTokenRes.Error != "" {
		t.Errorf("expected error: %s, got: %s", "", refreshTokenRes.Error)
	}

	if refreshTokenRes.Token == grantAuthRes.Token {
		t.Errorf("expected token to be different: %s, got: %s", grantAuthRes.Token, refreshTokenRes.Token)
	}

	// Test 7: Verify token
	verifyTokenReq := &pb.VerifyTokenRequest{
		Token: refreshTokenRes.Token,
	}

	verifyTokenRes, err := client.VerifyToken(context.Background(), verifyTokenReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if verifyTokenRes.UserId != grantAuthRes.UserId {
		t.Errorf("expected id: %s, got: %s", grantAuthRes.UserId, verifyTokenRes.UserId)
	}

	if verifyTokenRes.Token == "" {
		t.Errorf("expected token: %s, got: %s", "token", verifyTokenRes.Token)
	}

	if verifyTokenRes.Error != "" {
		t.Errorf("expected error: %s, got: %s", "", verifyTokenRes.Error)
	}

	// Test 8: Delete auth
	deleteAuthReq := &pb.DeleteAuthRequest{
		UserId: userId,
		AppId:  appId,
	}

	deleteAuthRes, err := client.DeleteAuth(context.Background(), deleteAuthReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if deleteAuthRes.Error != "" {
		t.Errorf("expected error: %s, got: %s", "", deleteAuthRes.Error)
	}

	// Test 9: Get public key
	publicKeyRes, err := client.GetPublicKey(context.Background(), &pb.PublicKeyRequest{Target: "token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPublicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("could not convert public key: %v", err)
	}

	if !bytes.Equal(expectedPublicKeyBytes, publicKeyRes.PublicKey) {
		t.Errorf("expected public key: %s, got: %s", expectedPublicKeyBytes, publicKeyRes.PublicKey)
	}

	// Test 10: Flush db request
	flushResult, err := client.FlushDB(context.Background(), &pb.FlushDBRequest{Reason: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if flushResult.Error != "" {
		t.Errorf("expected error: %s, got: %s", "", flushResult.Error)
	}

	flushResult, err = client.FlushDB(context.Background(), &pb.FlushDBRequest{Reason: "not-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if flushResult.Error == "" {
		t.Errorf("expected error: %s, got: %s", "Invalid reason. Flush DB only for testing", flushResult.Error)
	}

	// Mock env variable to test error
	c.EnvGoEnv = "not-test"

	flushResult, err = client.FlushDB(context.Background(), &pb.FlushDBRequest{Reason: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if flushResult.Error == "" {
		t.Errorf("expected error: %s, got: %s", "Invalid reason. Flush DB only for testing", flushResult.Error)
	}

	// Restore env variable
	c.EnvGoEnv = "test"

}

package services

import (
	"context"
	"encoding/pem"
	"math/rand"
	"os"
	"simple-micro-auth/src/cert"
	c "simple-micro-auth/src/configs"
	m "simple-micro-auth/src/models"
	pb "simple-micro-auth/src/proto"
	"strings"
	"time"
)

var (
	db           = NewDBHandler()
	tokenHandler = NewTokenHandler()
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
}

func (service *AuthServiceServer) CreateAuth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	newCredentialsDTO := m.CredentialsDTO{
		UserId:   m.UUID(req.UserId),
		Password: req.Password,
	}
	err := db.CreateCredentials(newCredentialsDTO)
	if err != nil {
		return &pb.AuthResponse{UserId: "", Token: "", Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	tokenTtl, err := time.ParseDuration(req.Ttl)
	if err != nil {
		tokenTtl = c.EnvJWTExpiration
	}

	token, err := tokenHandler.CreateToken(
		m.UUID(req.UserId),
		time.Now().Unix(),
		time.Now().Add(tokenTtl).Unix(),
		rand.Int63(),
		cert.PrivateKey,
	)
	if err != nil {
		return &pb.AuthResponse{UserId: "", Token: "", Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	return &pb.AuthResponse{UserId: req.UserId, Token: token, Error: ""}, nil
}

func (service *AuthServiceServer) UpdateAuth(ctx context.Context, req *pb.UpdateAuthRequest) (*pb.AuthResponse, error) {
	updCredentialsDTO := m.CredentialsDTOUpdate{
		UserId:      m.UUID(req.UserId),
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}
	err := db.UpdateCredentials(updCredentialsDTO)
	if err != nil {
		return &pb.AuthResponse{UserId: "", Token: "", Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	tokenTtl, err := time.ParseDuration(req.Ttl)
	if err != nil {
		tokenTtl = c.EnvJWTExpiration
	}

	token, err := tokenHandler.CreateToken(
		m.UUID(req.UserId),
		time.Now().Unix(),
		time.Now().Add(tokenTtl).Unix(),
		rand.Int63(),
		cert.PrivateKey,
	)
	if err != nil {
		return &pb.AuthResponse{UserId: "", Token: "", Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	return &pb.AuthResponse{UserId: req.UserId, Token: token, Error: ""}, nil
}

func (service *AuthServiceServer) DeleteAuth(ctx context.Context, req *pb.DeleteAuthRequest) (*pb.DeleteAuthResponse, error) {
	err := db.DeleteCredentials(m.UUID(req.UserId))
	if err != nil {
		return &pb.DeleteAuthResponse{Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	return &pb.DeleteAuthResponse{Error: ""}, nil
}

func (service *AuthServiceServer) GrantAuth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	compareCredentialsDT := m.CredentialsDTO{
		UserId:   m.UUID(req.UserId),
		Password: req.Password,
	}

	err := db.VerifyCredentials(compareCredentialsDT)
	if err != nil {
		return &pb.AuthResponse{UserId: "", Token: "", Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	tokenTtl, err := time.ParseDuration(req.Ttl)
	if err != nil {
		tokenTtl = c.EnvJWTExpiration
	}

	token, err := tokenHandler.CreateToken(
		m.UUID(req.UserId),
		time.Now().Unix(),
		time.Now().Add(tokenTtl).Unix(),
		rand.Int63(),
		cert.PrivateKey,
	)
	if err != nil {
		return &pb.AuthResponse{UserId: "", Token: "", Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	return &pb.AuthResponse{UserId: req.UserId, Token: token, Error: ""}, nil
}

func (service *AuthServiceServer) VerifyCredentials(ctx context.Context, req *pb.CredentialsRequest) (*pb.VerifyResponse, error) {
	compareCredentialsDT := m.CredentialsDTO{
		UserId:   m.UUID(req.UserId),
		Password: req.Password,
	}

	err := db.VerifyCredentials(compareCredentialsDT)
	if err != nil {
		return &pb.VerifyResponse{Success: false, Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	return &pb.VerifyResponse{Success: true, Error: ""}, nil
}

func (service *AuthServiceServer) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.AuthResponse, error) {
	userId, err := tokenHandler.VerifyToken(req.Token, time.Now().Unix(), cert.PublicKey)

	if err != nil {
		return &pb.AuthResponse{UserId: "", Token: "", Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	return &pb.AuthResponse{UserId: string(userId), Token: req.Token, Error: ""}, nil
}

func (service *AuthServiceServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.AuthResponse, error) {
	tokenTtl, err := time.ParseDuration(req.Ttl)
	if err != nil {
		tokenTtl = c.EnvJWTExpiration
	}

	response := tokenHandler.RefreshToken(req.Token, tokenTtl)

	return &pb.AuthResponse{UserId: string(response.UserId), Token: response.Token, Error: strings.ToValidUTF8(response.Error, "UTF-8_BUGFIX")}, nil
}

/**
 * Get public key
 */
func (service *AuthServiceServer) GetPublicKey(ctx context.Context, req *pb.PublicKeyRequest) (*pb.PublicKeyResponse, error) {

	target := req.Target

	// Read the contents of the .pem file
	publicKeyPEM, err := os.ReadFile("cert/" + target + "/public.pem")
	if err != nil {
		return &pb.PublicKeyResponse{
			PublicKey: []byte{},
			Error:     strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX"),
		}, nil
	}

	// Decode the pem file
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)

	// Create the response message and set the PublicKey field
	return &pb.PublicKeyResponse{
		PublicKey: publicKeyBlock.Bytes,
		Error:     "",
	}, nil
}

func (service *AuthServiceServer) FlushDB(ctx context.Context, req *pb.FlushDBRequest) (*pb.FlushDBResponse, error) {

	reason := req.Reason

	if reason != "test" || c.EnvGoEnv != "test" {
		return &pb.FlushDBResponse{Error: "Invalid reason. Flush DB only for testing"}, nil
	}

	err := db.FlushDB()
	if err != nil {
		return &pb.FlushDBResponse{Error: strings.ToValidUTF8(err.Error(), "UTF-8_BUGFIX")}, nil
	}

	return &pb.FlushDBResponse{Error: ""}, nil
}

func (service *AuthServiceServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	if req.Message == "ping" {
		return &pb.PingResponse{Message: "pong"}, nil
	} else {
		return &pb.PingResponse{Message: "Hello there!"}, nil
	}
}

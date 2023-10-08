package services

import (
	"context"
	"encoding/pem"
	"os"
	"simple-micro-auth/src/cert"
	m "simple-micro-auth/src/models"
	pb "simple-micro-auth/src/proto"
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
	newAuthDTO := m.AuthDTO{
		Id:         req.Id,
		LookupHash: req.LookupHash,
		Password:   req.Password,
	}
	response := db.CreateAuth(newAuthDTO)

	return &pb.AuthResponse{Id: response.Id, Token: response.Token, Error: response.Error}, nil
}

func (service *AuthServiceServer) UpdateAuth(ctx context.Context, req *pb.UpdateAuthRequest) (*pb.AuthResponse, error) {
	updAuthDTO := m.AuthDTOUpdate{
		Id:          req.Id,
		LookupHash:  req.LookupHash,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}
	response := db.UpdateAuth(updAuthDTO)

	return &pb.AuthResponse{Id: response.Id, Token: response.Token, Error: response.Error}, nil
}

func (service *AuthServiceServer) DeleteAuth(ctx context.Context, req *pb.DeleteAuthRequest) (*pb.DeleteAuthResponse, error) {
	result := db.DeleteAuth(req.LookupHash)

	response := "ApplicationError: " + result.Error()

	return &pb.DeleteAuthResponse{Error: response}, nil
}

func (service *AuthServiceServer) CompareAuth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	compareAuthDT := m.AuthDTO{
		Id:         req.Id,
		LookupHash: req.LookupHash,
		Password:   req.Password,
	}

	response := db.CompareAuth(compareAuthDT)

	return &pb.AuthResponse{Id: response.Id, Token: response.Token, Error: response.Error}, nil
}

func (service *AuthServiceServer) VerifyToken(ctx context.Context, req *pb.TokenRequest) (*pb.AuthResponse, error) {
	id, err := tokenHandler.VerifyToken(req.Token, time.Now().Unix(), cert.PublicKey)

	if err != nil {
		return &pb.AuthResponse{Id: id, Token: req.Token, Error: "TokenError: " + err.Error()}, nil
	}

	return &pb.AuthResponse{Id: id, Token: req.Token, Error: ""}, nil
}

func (service *AuthServiceServer) RefreshToken(ctx context.Context, req *pb.TokenRequest) (*pb.AuthResponse, error) {
	response := tokenHandler.RefreshToken(req.Token)

	return &pb.AuthResponse{Id: response.Id, Token: response.Token, Error: response.Error}, nil
}

/**
 * Get public key
 */
func (service *AuthServiceServer) GetPublicKey(ctx context.Context, req *pb.PublicKeyRequest) (*pb.PublicKeyResponse, error) {

	target := req.Target

	// Read the contents of the .pem file
	publicKeyPEM, err := os.ReadFile("cert/" + target + "/public.pem")
	if err != nil {
		return nil, err
	}

	// Decode the pem file
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)

	// Create the response message and set the PublicKey field
	response := &pb.PublicKeyResponse{
		PublicKey: publicKeyBlock.Bytes,
	}

	return response, nil
}

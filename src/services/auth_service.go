package services

import (
	"context"
	"m-cafe-auth/src/configs"
	pb "m-cafe-auth/src/proto"
)

var (
	db           = configs.NewDBHandler()
	tokenHandler = configs.NewTokenHandler()
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
}

func (service *AuthServiceServer) CreateAuth(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	newAuthDTO := configs.AuthDTO{
		Id:         req.Id,
		LookupHash: req.LookupHash,
		Password:   req.Password,
	}
	response := db.CreateAuth(newAuthDTO)

	return &pb.AuthResponse{Id: response.Id, Token: response.Token, Error: response.Error}, nil
}

func (service *AuthServiceServer) UpdateAuth(ctx context.Context, req *pb.UpdateAuthRequest) (*pb.AuthResponse, error) {
	updAuthDTO := configs.AuthDTOUpdate{
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
	compareAuthDT := configs.AuthDTO{
		Id:         req.Id,
		LookupHash: req.LookupHash,
		Password:   req.Password,
	}

	response := db.CompareAuth(compareAuthDT)

	return &pb.AuthResponse{Id: response.Id, Token: response.Token, Error: response.Error}, nil
}

func (service *AuthServiceServer) VerifyToken(ctx context.Context, req *pb.TokenRequest) (*pb.AuthResponse, error) {
	id, err := tokenHandler.VerifyToken(req.Token)

	if err != nil {
		return &pb.AuthResponse{Id: id, Token: req.Token, Error: "TokenError: " + err.Error()}, nil
	}

	return &pb.AuthResponse{Id: id, Token: req.Token, Error: ""}, nil
}

func (service *AuthServiceServer) RefreshToken(ctx context.Context, req *pb.TokenRequest) (*pb.AuthResponse, error) {
	response := tokenHandler.RefreshToken(req.Token)

	return &pb.AuthResponse{Id: response.Id, Token: response.Token, Error: response.Error}, nil
}

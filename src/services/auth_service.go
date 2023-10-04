package services

import (
	"context"
	"m-cafe-auth/src/configs"
	pb "m-cafe-auth/src/proto"
)

var db = configs.NewDBHandler()

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
}

// func (service *AuthServiceServer) CreateAuth(ctx context.Context, req *pb.CreateAuthRequest) (*pb.CreateAuthResponse, error) {
// 	resp, err := db.CreateAuth(req.Id)

// 	if err != nil {
// 			return nil, err
// 	}

// 	return &pb.AuthResponse{Id: resp.Id.String(), Name: resp.Name, Location: resp.Location, Title: resp.Title}, nil
// }

func (service *AuthServiceServer) CreateAuth(ctx context.Context, req *pb.CreateAuthRequest) (*pb.CreateAuthResponse, error) {
	newAuthDTN := configs.AuthDTN{
		Id:         req.Id,
		LookupHash: req.LookupHash,
		Password:   req.Password,
	}
	response := db.CreateAuth(newAuthDTN)

	return &pb.CreateAuthResponse{Success: response.Success, Token: response.Token}, nil
}

func (service *AuthServiceServer) UpdateAuth(ctx context.Context, req *pb.UpdateAuthRequest) (*pb.UpdateAuthResponse, error) {
	updAuthDTN := configs.AuthDTN{
		Id:         req.Id,
		LookupHash: req.LookupHash,
		Password:   req.Password,
	}
	response := db.UpdateAuth(updAuthDTN)

	return &pb.UpdateAuthResponse{Success: response.Success, Token: response.Token}, nil
}

func (service *AuthServiceServer) DeleteAuth(ctx context.Context, req *pb.DeleteAuthRequest) (*pb.DeleteAuthResponse, error) {
	result := db.DeleteAuth(req.LookupHash)

	return &pb.DeleteAuthResponse{Success: result}, nil
}

func (service *AuthServiceServer) CompareAuth(ctx context.Context, req *pb.CompareAuthRequest) (*pb.CompareAuthResponse, error) {
	compareAuthDT := configs.AuthDT{
		LookupHash: req.LookupHash,
		Password:   req.Password,
	}

	result := db.CompareAuth(compareAuthDT)

	return &pb.CompareAuthResponse{IsMatch: result}, nil
}

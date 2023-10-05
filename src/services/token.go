package services

import (
	"fmt"
	"math/rand"
	c "simple-micro-auth/src/configs"
	m "simple-micro-auth/src/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ITokenHandler interface {
	CreateToken(id int64, expiresAt int64, noise int64, secret string) (string, error)
	VerifyToken(token string, timeNow int64, secret string) (int64, error)
	RefreshToken(token string) *m.AuthResponse
}

type tokenHandlerImpl struct{}

func (handler *tokenHandlerImpl) CreateToken(id int64, expiresAt int64, noise int64, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":         id,
		"rand":       noise,
		"expires_at": expiresAt,
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (handler *tokenHandlerImpl) VerifyToken(token string, timeNow int64, secret string) (int64, error) {

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		err = fmt.Errorf("invalid token or signature")
		return 0, err
	}

	if !parsedToken.Valid {
		err = fmt.Errorf("invalid token")
		return 0, err
	}

	if parsedToken.Method != jwt.SigningMethodHS256 {
		err = fmt.Errorf("unexpected signing method")
		return 0, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		err = fmt.Errorf("claims malformed")
		return 0, err
	}

	expiresAt, ok := claims["expires_at"].(float64)
	if !ok {
		err = fmt.Errorf("expires_at claim malformed")
		return 0, err
	}

	if int64(expiresAt) < timeNow {
		err = fmt.Errorf("token expired")
		return 0, err
	}

	id, ok := claims["id"].(float64)
	if !ok {
		err = fmt.Errorf("id claim malformed")
		return 0, err
	}

	return int64(id), nil
}

func (handler *tokenHandlerImpl) RefreshToken(token string) *m.AuthResponse {

	id, err := handler.VerifyToken(token, time.Now().Unix(), c.EnvJWTSecret)
	if err != nil {
		return &m.AuthResponse{
			Id:    id,
			Token: token,
			Error: "TokenError: " + err.Error(),
		}
	}

	tokenString, err := handler.CreateToken(id, time.Now().Add(c.EnvJWTExpiration).Unix(), rand.Int63(), c.EnvJWTSecret)
	if err != nil {
		return &m.AuthResponse{
			Id:    id,
			Token: tokenString,
			Error: "TokenError: " + err.Error(),
		}
	}

	return &m.AuthResponse{
		Id:    id,
		Token: tokenString,
		Error: "",
	}
}

func NewTokenHandler() ITokenHandler {
	return &tokenHandlerImpl{}
}

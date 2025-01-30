package services

import (
	"crypto/rsa"
	"fmt"
	"math/rand"
	"simple-micro-auth/src/cert"
	m "simple-micro-auth/src/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ITokenHandler interface {
	CreateToken(userId m.UUID, timeNow int64, expiresAt int64, noise int64, key *rsa.PrivateKey) (string, error)
	VerifyToken(token string, timeNow int64, key any) (m.UUID, error)
	RefreshToken(token string, tokenTtl time.Duration) *m.AuthResponse
}

type tokenHandlerImpl struct{}

func (handler *tokenHandlerImpl) CreateToken(userId m.UUID, timeNow int64, expiresAt int64, noise int64, key *rsa.PrivateKey) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"id":   userId,
		"rand": noise,
		"exp":  expiresAt,
		"iat":  timeNow,
		"nbf":  timeNow,
		"iss":  "simple-micro-auth",
	})

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (handler *tokenHandlerImpl) VerifyToken(token string, timeNow int64, key any) (m.UUID, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return key, nil
	})

	if err != nil {
		err = fmt.Errorf("invalid token or signature")
		return "", err
	}

	if !parsedToken.Valid {
		err = fmt.Errorf("invalid token")
		return "", err
	}

	if parsedToken.Method != jwt.SigningMethodRS256 {
		err = fmt.Errorf("unexpected signing method")
		return "", err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		err = fmt.Errorf("claims malformed")
		return "", err
	}

	expiresAt, ok := claims["exp"].(float64)
	if !ok {
		err = fmt.Errorf("exp claim malformed")
		return "", err
	}

	if int64(expiresAt) < timeNow {
		err = fmt.Errorf("token expired")
		return "", err
	}

	userId, ok := claims["id"]
	if !ok {
		err = fmt.Errorf("id claim malformed")
		return "", err
	}

	return m.UUID(userId.(string)), nil
}

func (handler *tokenHandlerImpl) RefreshToken(token string, tokenTtl time.Duration) *m.AuthResponse {

	userId, err := handler.VerifyToken(token, time.Now().Unix(), cert.PublicKey)
	if err != nil {
		return &m.AuthResponse{
			UserId: userId,
			Token:  token,
			Error:  "TokenError: " + err.Error(),
		}
	}

	tokenString, err := handler.CreateToken(userId, time.Now().Unix(), time.Now().Add(tokenTtl).Unix(), rand.Int63(), cert.PrivateKey)
	if err != nil {
		return &m.AuthResponse{
			UserId: userId,
			Token:  tokenString,
			Error:  "TokenError: " + err.Error(),
		}
	}

	return &m.AuthResponse{
		UserId: userId,
		Token:  tokenString,
		Error:  "",
	}
}

func NewTokenHandler() ITokenHandler {
	return &tokenHandlerImpl{}
}

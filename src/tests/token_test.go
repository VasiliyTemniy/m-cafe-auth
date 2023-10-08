package tests

import (
	"crypto/x509"
	"fmt"
	"simple-micro-auth/src/cert"
	s "simple-micro-auth/src/services"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

var (
	tokenHandler = s.NewTokenHandler()
)

const (
	mockExpiresAt    = int64(100000000000)
	mockTimeNow      = int64(99990)
	mockRandomNumber = int64(12345)
	mockId           = int64(123)
)

func init() {
	cert.ReadCertificates("token")
}

func TestCreateAndVerifyToken(t *testing.T) {

	// Test case 1: Valid token should be created
	validTokenString, err := tokenHandler.CreateToken(mockId, mockTimeNow, mockExpiresAt, mockRandomNumber, cert.PrivateKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	id, err := tokenHandler.VerifyToken(validTokenString, mockTimeNow, cert.PublicKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if id != mockId {
		t.Errorf("Expected ID: %d, got: %d", mockId, id)
	}

	// Test case 2: Invalid token
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVzX2F0IjoxMDAwMDAwMDAwMDAsImlkIjoxMjMsInJhbmQiOjEyMzQ1fQ.55lgZVHQ0Vy-uPWcgov19yUeJQd6sEcUsrb1HnLLF-E"
	expectedErr := fmt.Errorf("invalid token or signature")

	id, err = tokenHandler.VerifyToken(invalidToken, mockTimeNow, cert.PublicKey)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 3: expired token
	expectedErr = fmt.Errorf("token expired")

	muchMoreMockTimeNow := mockExpiresAt + 1000

	id, err = tokenHandler.VerifyToken(validTokenString, muchMoreMockTimeNow, cert.PublicKey)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 4: unexpected signing method
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	invalidSignedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   id,
		"rand": mockRandomNumber,
		"exp":  mockExpiresAt,
		"iat":  mockTimeNow,
		"nbf":  mockTimeNow,
		"iss":  "simple-micro-auth",
	}).SignedString(publicKeyBytes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expectedButInterceptedErr := fmt.Errorf("invalid token or signature")
	expectedErr = fmt.Errorf("unexpected signing method")

	id, err = tokenHandler.VerifyToken(invalidSignedToken, mockTimeNow, cert.PublicKey)
	if err.Error() != expectedErr.Error() && err.Error() != expectedButInterceptedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 5: malformed exp claim
	invalidExpClaimToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"id":   id,
		"rand": mockRandomNumber,
		// "exp":  "invalid",
		"iat": mockTimeNow,
		"nbf": mockTimeNow,
		"iss": "simple-micro-auth",
	}).SignedString(cert.PrivateKey)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expectedErr = fmt.Errorf("exp claim malformed")

	id, err = tokenHandler.VerifyToken(invalidExpClaimToken, mockTimeNow, cert.PublicKey)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 6: malformed id claim
	invalidIdClaimToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"id":   "invalid",
		"rand": mockRandomNumber,
		"exp":  mockExpiresAt,
		"iat":  mockTimeNow,
		"nbf":  mockTimeNow,
		"iss":  "simple-micro-auth",
	}).SignedString(cert.PrivateKey)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expectedErr = fmt.Errorf("id claim malformed")

	id, err = tokenHandler.VerifyToken(invalidIdClaimToken, mockTimeNow, cert.PublicKey)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}
}

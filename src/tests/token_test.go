package tests

import (
	"fmt"
	s "simple-micro-auth/src/services"
	"testing"
)

var (
	tokenHandler = s.NewTokenHandler()
)

const (
	validExpectedToken         = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVzX2F0IjoxMDAwMDAwMDAwMDAsImlkIjoxMjMsInJhbmQiOjEyMzQ1fQ.LdolfV3z2h-4b-M7fYNAktz0UU2RtuS0CD2UdRK_iog"
	invalidToken               = "eyJhbGciOiJIUzI1NiIsF0IjoxMDAwMDAwMDAwMDAsImlkIjoxMjMsInJhbmQiOjEyMzQ1fQ.V5z1mWBH9LrMo49AFMT-CYpuAEFQ"
	invalidIdClaimToken        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVzX2F0IjoxMDAwMDAwMDAwMDAsImlkIjoiMTIzIiwicmFuZCI6MTIzNDV9.KPTmtGzVG2ED4Z5cgTQuhdC9Wt-Y3F4aQJXlGuPNeYo"
	invalidExpiresAtClaimToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVzX2F0IjoiMTAwMDAwMDAwMDAwIiwiaWQiOjEyMywicmFuZCI6MTIzNDV9.1_t6KnWT8ds8B4Bg86FmYOXxMHoJxi_LWqchQrdKK8o"
	invalidSignatureToken      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVzX2F0IjoxMDAwMDAwMDAwMDAsImlkIjoxMjMsInJhbmQiOjEyMzQ1fQ.55lgZVHQ0Vy-uPWcgov19yUeJQd6sEcUsrb1HnLLF-E"
	invalidMethodToken         = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJqb3BhIjoiMTMyIiwiZXhwaXJlc19hdCI6MTAwMDAwMDAwMDAwLCJpZCI6MTIzLCJyYW5kIjoxMjM0NX0.6Ei6AP9rDqtPF5AhKOmg7ZDcpA_amX4azbHGPZX-N0ZU4RV5746SsvK9pK-7HdxW"
	mockExpiresAt              = int64(100000000000)
	mockEnvJWTSecret           = "JustATestSecret"
	mockRandomNumber           = int64(12345)
	mockId                     = int64(123)
)

func TestCreateToken(t *testing.T) {
	// Test case 1: Valid token should be created

	tokenString, err := tokenHandler.CreateToken(mockId, mockExpiresAt, mockRandomNumber, mockEnvJWTSecret)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if tokenString != validExpectedToken {
		t.Errorf("expected token: %s, got: %s", validExpectedToken, tokenString)
	}
}

func TestVerifyToken(t *testing.T) {
	// Test case 1: Valid token, not expired
	token := validExpectedToken
	mockTimeNow := mockExpiresAt - 1000
	expectedID := mockId

	id, err := tokenHandler.VerifyToken(token, mockTimeNow, mockEnvJWTSecret)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if id != expectedID {
		t.Errorf("Expected ID: %d, got: %d", expectedID, id)
	}

	// Test case 2: Invalid token
	token = invalidToken
	expectedErr := fmt.Errorf("invalid token or signature")

	id, err = tokenHandler.VerifyToken(token, mockTimeNow, mockEnvJWTSecret)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 3: Expired token
	token = validExpectedToken
	expectedErr = fmt.Errorf("token expired")

	timeNow := mockExpiresAt + 1000

	id, err = tokenHandler.VerifyToken(token, timeNow, mockEnvJWTSecret)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 4: Unexpected signing method
	token = invalidMethodToken
	expectedErr = fmt.Errorf("unexpected signing method")

	id, err = tokenHandler.VerifyToken(token, mockTimeNow, mockEnvJWTSecret)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 5: Malformed exp claim
	token = invalidExpiresAtClaimToken
	expectedErr = fmt.Errorf("exp claim malformed")

	id, err = tokenHandler.VerifyToken(token, mockTimeNow, mockEnvJWTSecret)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 6: Malformed id claim
	token = invalidIdClaimToken
	expectedErr = fmt.Errorf("id claim malformed")

	id, err = tokenHandler.VerifyToken(token, mockTimeNow, mockEnvJWTSecret)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}

	// Test case 7: Invalid signature
	token = validExpectedToken
	expectedErr = fmt.Errorf("invalid token or signature")

	secret := "invalid"

	id, err = tokenHandler.VerifyToken(token, mockTimeNow, secret)
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if id != 0 {
		t.Errorf("Expected ID: 0, got: %d", id)
	}
}

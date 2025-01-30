package tests

import (
	"simple-micro-auth/src/cert"
	m "simple-micro-auth/src/models"
	s "simple-micro-auth/src/services"
	"testing"
)

var (
	db = s.NewDBHandler()
)

const (
	userId   = "10222fc6-148d-464c-9770-8f6f187d0b43"
	appId    = "10222fc6-148d-464c-9770-8f6f187d0b44"
	password = "test"
)

func init() {
	cert.ReadCertificates("token")
}

func TestCreateCredentials(t *testing.T) {
	db.FlushDB()

	err := db.CreateCredentials(m.CredentialsDTO{
		UserId:   userId,
		AppId:    appId,
		Password: password,
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}
}

func TestVerifyCredentials(t *testing.T) {
	db.FlushDB()

	err := db.CreateCredentials(m.CredentialsDTO{
		UserId:   userId,
		AppId:    appId,
		Password: password,
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 1: Valid credentials
	err = db.VerifyCredentials(m.CredentialsDTO{
		UserId:   userId,
		AppId:    appId,
		Password: password,
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 2: Invalid credentials
	err = db.VerifyCredentials(m.CredentialsDTO{
		UserId:   userId,
		AppId:    appId,
		Password: password + "1",
	})

	if err == nil {
		t.Errorf("expected error: %s, got: %s", "something", "nothing")
	}
}

func TestUpdateCredentials(t *testing.T) {
	db.FlushDB()

	err := db.CreateCredentials(m.CredentialsDTO{
		UserId:   userId,
		AppId:    appId,
		Password: password,
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 1: Valid credentials
	err = db.UpdateCredentials(m.CredentialsDTOUpdate{
		UserId:      userId,
		AppId:       appId,
		OldPassword: password,
		NewPassword: password + "1",
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 2: Invalid credentials
	err = db.UpdateCredentials(m.CredentialsDTOUpdate{
		UserId:      userId,
		AppId:       appId,
		OldPassword: "something_totally_different",
		NewPassword: "test123",
	})

	if err == nil {
		t.Errorf("expected error: %s, got: %s", "something", "nothing")
	}
}

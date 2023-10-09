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

func init() {
	cert.ReadCertificates("token")
}

func TestCreateCredentials(t *testing.T) {
	db.FlushDB()

	err := db.CreateCredentials(m.CredentialsDTO{
		LookupHash: "test",
		Password:   "test",
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}
}

func TestVerifyCredentials(t *testing.T) {
	db.FlushDB()

	err := db.CreateCredentials(m.CredentialsDTO{
		LookupHash: "test",
		Password:   "test",
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 1: Valid credentials
	err = db.VerifyCredentials(m.CredentialsDTO{
		LookupHash: "test",
		Password:   "test",
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 2: Invalid credentials
	err = db.VerifyCredentials(m.CredentialsDTO{
		LookupHash: "test",
		Password:   "test1",
	})

	if err == nil {
		t.Errorf("expected error: %s, got: %s", "something", err.Error())
	}
}

func TestUpdateCredentials(t *testing.T) {
	db.FlushDB()

	err := db.CreateCredentials(m.CredentialsDTO{
		LookupHash: "test",
		Password:   "test",
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 1: Valid credentials
	err = db.UpdateCredentials(m.CredentialsDTOUpdate{
		LookupHash:  "test",
		OldPassword: "test",
		NewPassword: "test1",
	})

	if err != nil {
		t.Errorf("expected error to be empty, got: %s", err.Error())
	}

	// Test case 2: Invalid credentials
	err = db.UpdateCredentials(m.CredentialsDTOUpdate{
		LookupHash:  "test",
		OldPassword: "something_totally_different",
		NewPassword: "test123",
	})

	if err == nil {
		t.Errorf("expected error: %s, got: %s", "something", err.Error())
	}
}

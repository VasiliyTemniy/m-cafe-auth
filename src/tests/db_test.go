package tests

import (
	"database/sql"
	"fmt"
	"log"
	"simple-micro-auth/src/cert"
	c "simple-micro-auth/src/configs"
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

func flushDB() error {
	postgresConfig := c.EnvPostgresConfig

	postgresqlDbInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=%s",
		postgresConfig.Host,
		postgresConfig.Port,
		postgresConfig.User,
		postgresConfig.Password,
		postgresConfig.DBName,
		postgresConfig.SslMode,
	)

	db, err := sql.Open("postgres", postgresqlDbInfo)
	if err != nil {
		log.Fatal("Error opening db")
		log.Fatal("DB connection string: ", postgresqlDbInfo)
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging db")
		panic(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS auth (
		lookup_hash varchar(100) UNIQUE NOT NULL PRIMARY KEY,
		password_hash varchar(100) NOT NULL
	)`)

	if err != nil {
		log.Fatal("Error creating auth table")
	}

	_, err = db.Exec(`DELETE FROM auth`)

	return err
}

func TestCreateAuth(t *testing.T) {
	flushDB()

	newAuth := db.CreateAuth(m.AuthDTO{
		Id:         123,
		LookupHash: "test",
		Password:   "test",
	})

	if newAuth.Id != 123 {
		t.Errorf("expected id: %s, got: %s", "123", fmt.Sprintf("%v", (newAuth.Id)))
	}

	if newAuth.Token == "" {
		t.Errorf("expected token: %s, got: %s", "something", newAuth.Token)
	}

	if newAuth.Error != "" {
		t.Errorf("expected error to be empty, got: %s", newAuth.Error)
	}
}

func TestVerifyAuth(t *testing.T) {
	flushDB()

	db.CreateAuth(m.AuthDTO{
		Id:         123,
		LookupHash: "test",
		Password:   "test",
	})

	// Test case 1: Valid auth
	compareAuth := db.CompareAuth(m.AuthDTO{
		Id:         123,
		LookupHash: "test",
		Password:   "test",
	})

	if compareAuth.Id != 123 {
		t.Errorf("expected id: %s, got: %s", "123", fmt.Sprintf("%v", (compareAuth.Id)))
	}

	if compareAuth.Token == "" {
		t.Errorf("expected token: %s, got: %s", "something", compareAuth.Token)
	}

	if compareAuth.Error != "" {
		t.Errorf("expected error to be empty, got: %s", compareAuth.Error)
	}

	// Test case 2: Invalid auth
	invalidCompareAuth := db.CompareAuth(m.AuthDTO{
		Id:         123,
		LookupHash: "test",
		Password:   "test1",
	})

	if invalidCompareAuth.Id != 123 {
		t.Errorf("expected id: %s, got: %s", "123", fmt.Sprintf("%v", (invalidCompareAuth.Id)))
	}

	if invalidCompareAuth.Token != "" {
		t.Errorf("expected token to be empty, got: %s", invalidCompareAuth.Token)
	}

	if invalidCompareAuth.Error == "" {
		t.Errorf("expected error: %s, got: %s", "something", invalidCompareAuth.Error)
	}
}

func TestUpdateAuth(t *testing.T) {
	flushDB()

	db.CreateAuth(m.AuthDTO{
		Id:         123,
		LookupHash: "test",
		Password:   "test",
	})

	// Test case 1: Valid auth
	updatedAuth := db.UpdateAuth(m.AuthDTOUpdate{
		Id:          123,
		LookupHash:  "test",
		OldPassword: "test",
		NewPassword: "test1",
	})

	if updatedAuth.Id != 123 {
		t.Errorf("expected id: %s, got: %s", "123", fmt.Sprintf("%v", (updatedAuth.Id)))
	}

	if updatedAuth.Token == "" {
		t.Errorf("expected token: %s, got: %s", "something", updatedAuth.Token)
	}

	if updatedAuth.Error != "" {
		t.Errorf("expected error to be empty, got: %s", updatedAuth.Error)
	}

	// Test case 2: Invalid auth
	invalidUpdatedAuth := db.UpdateAuth(m.AuthDTOUpdate{
		Id:          123,
		LookupHash:  "test",
		OldPassword: "something_totally_different",
		NewPassword: "test123",
	})

	if invalidUpdatedAuth.Id != 123 {
		t.Errorf("expected id: %s, got: %s", "123", fmt.Sprintf("%v", (invalidUpdatedAuth.Id)))
	}

	if invalidUpdatedAuth.Token != "" {
		t.Errorf("expected token to be empty, got: %s", invalidUpdatedAuth.Token)
	}

	if invalidUpdatedAuth.Error == "" {
		t.Errorf("expected error: %s, got: %s", "something", invalidUpdatedAuth.Error)
	}
}

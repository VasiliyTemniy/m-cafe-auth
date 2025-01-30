package services

import (
	"database/sql"
	"fmt"
	"log"
	c "simple-micro-auth/src/configs"
	m "simple-micro-auth/src/models"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

type dbHandler interface {
	CreateCredentials(auth m.CredentialsDTO) error
	UpdateCredentials(auth m.CredentialsDTOUpdate) error
	DeleteCredentials(userId m.UUID, appId m.UUID) error
	VerifyCredentials(credentials m.CredentialsDTO) error
	FlushDB() error
}

type dbHandlerImpl struct {
	db *sql.DB
}

func (handler *dbHandlerImpl) CreateCredentials(auth m.CredentialsDTO) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(auth.Password), c.EnvBcryptCost)

	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error creating password hash with bcrypt")
		return err
	}

	_, err = handler.db.Exec(`INSERT INTO auth(user_id, app_id, password_hash)
	VALUES($1, $2, $3)`, auth.UserId, auth.AppId, passwordHash)

	if err != nil {
		if err.Error() != `pq: duplicate key value violates unique constraint "auth_pkey"` {
			fmt.Println(err)
			return err
		}
		err = fmt.Errorf("error creating credentials in db")
		return err
	}

	return err
}

func (handler *dbHandlerImpl) UpdateCredentials(auth m.CredentialsDTOUpdate) error {

	credentialsDTOToCompare := m.CredentialsDTO{
		UserId:     auth.UserId,
		AppId:      auth.AppId,
		Password:   auth.OldPassword,
	}

	err := handler.VerifyCredentials(credentialsDTOToCompare)
	if err != nil {
		return err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(auth.NewPassword), c.EnvBcryptCost)
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error creating this password hash with bcrypt")
		return err
	}

	_, err = handler.db.Exec(`UPDATE auth SET password_hash = $1 WHERE user_id = $2 AND app_id = $3`, passwordHash, auth.UserId, auth.AppId)
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error updating password_hash in db while this user_id and app_id were found: %s and %s", auth.UserId, auth.AppId)
		return err
	}

	return err
}

func (handler *dbHandlerImpl) DeleteCredentials(userId m.UUID, appId m.UUID) error {

	_, err := handler.db.Exec(`DELETE FROM auth WHERE user_id = $1 AND app_id = $2`, userId, appId)
	if err != nil {
		log.Println(err)
		err = fmt.Errorf("error deleting credentials from db")
		return err
	}

	return err
}

func (handler *dbHandlerImpl) VerifyCredentials(credentials m.CredentialsDTO) error {

	storedPasswordHashRow, err := handler.db.Query(`SELECT password_hash FROM auth WHERE user_id = $1 AND app_id = $2`, credentials.UserId, credentials.AppId)
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error reading password_hash from db")
		return err
	}
	defer storedPasswordHashRow.Close()

	var storedPasswordHash string

	if storedPasswordHashRow.Next() {
		err = storedPasswordHashRow.Scan(&storedPasswordHash)
		if err != nil {
			fmt.Println(err)
			err = fmt.Errorf("error reading password_hash from db")
			return err
		}
	}

	if storedPasswordHash == "" {
		err = fmt.Errorf("lookupHash not found")
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(credentials.Password))
	if err != nil && err.Error() == "crypto/bcrypt: hashedPassword is not the hash of the given password" {
		err = fmt.Errorf("invalid password")
	}

	return err
}

func (handler *dbHandlerImpl) FlushDB() error {
	_, err := handler.db.Exec(`DELETE FROM auth`)

	if err != nil {
		log.Println(err)
		err = fmt.Errorf("error flushing db")
		return err
	}

	return err
}

func NewDBHandler() dbHandler {

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
		log.Fatal("error opening db")
		log.Fatal("db connection string: ", postgresqlDbInfo)
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("error pinging db")
		panic(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS auth (
		user_id UUID NOT NULL,
		app_id UUID NOT NULL,
		password_hash varchar(100) NOT NULL,
		CONSTRAINT auth_user_id_app_id_pkey PRIMARY KEY (user_id, app_id)
	)`)
	if err != nil {
		log.Fatal("error creating auth table")
		panic(err)
	} else {
		log.Println("auth table exists or created")
	}

	return &dbHandlerImpl{db}
}

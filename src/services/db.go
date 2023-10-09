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
	DeleteCredentials(lookupHash string) error
	VerifyCredentials(credentials m.CredentialsDTO) error
	FlushDB() error
}

type dbHandlerImpl struct {
	db *sql.DB
}

func (handler *dbHandlerImpl) CreateCredentials(auth m.CredentialsDTO) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(auth.Password), c.EnvBcryptCost)

	if err != nil {
		return err
		// return &m.AuthResponse{
		// 	Id:    auth.Id,
		// 	Token: "",
		// 	Error: "Problem with creating this " + auth.Password + " password hash with bcrypt: " + err.Error(),
		// }
	}

	_, err = handler.db.Exec(`INSERT INTO auth(lookup_hash, password_hash)
	VALUES($1, $2)`, auth.LookupHash, passwordHash)

	if err != nil {
		return err
		// return &m.AuthResponse{
		// 	Id:    auth.Id,
		// 	Token: "",
		// 	Error: "Problem with creating new auth: " + err.Error(),
		// }
	}

	// tokenString, err := tokenHandler.CreateToken(
	// 	auth.Id,
	// 	time.Now().Unix(),
	// 	time.Now().Add(c.EnvJWTExpiration).Unix(),
	// 	rand.Int63(),
	// 	cert.PrivateKey,
	// )
	// if err != nil {
	// 	log.Println(err)
	// 	return &m.AuthResponse{
	// 		Id:    auth.Id,
	// 		Token: "",
	// 		Error: "Problem with signing token: " + err.Error(),
	// 	}
	// }

	return err
}

func (handler *dbHandlerImpl) UpdateCredentials(auth m.CredentialsDTOUpdate) error {

	credentialsDTOToCompare := m.CredentialsDTO{
		LookupHash: auth.LookupHash,
		Password:   auth.OldPassword,
	}

	err := handler.VerifyCredentials(credentialsDTOToCompare)
	if err != nil {
		return err
		// return &m.AuthResponse{
		// 	Id:    auth.Id,
		// 	Token: "",
		// 	Error: "Incorrect password",
		// }
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(auth.NewPassword), c.EnvBcryptCost)
	if err != nil {
		err = fmt.Errorf("Problem with creating this " + auth.NewPassword + " password hash with bcrypt: " + err.Error())
		return err
		// return &m.AuthResponse{
		// 	Id:    auth.Id,
		// 	Token: "",
		// 	Error: "Problem with creating this " + auth.NewPassword + " password hash with bcrypt: " + err.Error(),
		// }
	}

	_, err = handler.db.Exec(`UPDATE auth SET password_hash = $1 WHERE lookup_hash = $2`, passwordHash, auth.LookupHash)
	if err != nil {
		err = fmt.Errorf("Problem with updating password_hash in db while this lookup_hash was found: " + auth.LookupHash + " error: " + err.Error())
		return err

		// return &m.AuthResponse{
		// 	Id:    auth.Id,
		// 	Token: "",
		// 	Error: "Problem with updating password_hash in db while this lookup_hash was found: " + auth.LookupHash + " error: " + err.Error(),
		// }
	}

	// tokenString, err := tokenHandler.CreateToken(
	// 	auth.Id,
	// 	time.Now().Unix(),
	// 	time.Now().Add(c.EnvJWTExpiration).Unix(),
	// 	rand.Int63(),
	// 	cert.PrivateKey,
	// )
	// if err != nil {
	// 	log.Println(err)
	// 	return &m.AuthResponse{
	// 		Id:    auth.Id,
	// 		Token: "",
	// 		Error: "Problem with signing token: " + err.Error(),
	// 	}
	// }

	// return &m.AuthResponse{
	// 	Id:    auth.Id,
	// 	Token: tokenString,
	// 	Error: "",
	// }

	return err
}

func (handler *dbHandlerImpl) DeleteCredentials(lookupHash string) error {

	_, err := handler.db.Exec(`DELETE FROM auth WHERE lookup_hash = $1`, lookupHash)
	if err != nil {
		log.Println(err)
		return err
	}

	return err
}

func (handler *dbHandlerImpl) VerifyCredentials(credentials m.CredentialsDTO) error {

	storedPasswordHashRow, err := handler.db.Query(`SELECT password_hash FROM auth WHERE lookup_hash = $1`, credentials.LookupHash)
	if err != nil {
		return err
	}

	var storedPasswordHash string

	if storedPasswordHashRow.Next() {
		err = storedPasswordHashRow.Scan(&storedPasswordHash)
		if err != nil {
			return err
		}
	}

	return bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(credentials.Password))
}

func (handler *dbHandlerImpl) FlushDB() error {
	_, err := handler.db.Exec(`DELETE FROM auth`)

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
		panic(err)
	} else {
		log.Println("auth table exists or created")
	}

	return &dbHandlerImpl{db}
}

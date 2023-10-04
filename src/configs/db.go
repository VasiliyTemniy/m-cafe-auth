package configs

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

type dbHandler interface {
	CreateAuth(auth AuthDTN) *AuthResponse
	UpdateAuth(auth AuthDTN) *AuthResponse
	DeleteAuth(lookupHash string) bool
	CompareAuth(auth AuthDT) bool
}

type dbHandlerImpl struct {
	db *sql.DB
}

// CreateAuth implements dbHandler.
func (handler *dbHandlerImpl) CreateAuth(auth AuthDTN) *AuthResponse {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(auth.Password), EnvBcryptCost())

	if err != nil {
		panic(err)
	}

	_, err = handler.db.Exec(`INSERT INTO auth(lookup_hash, password_hash)
	VALUES($1, $2)`, auth.LookupHash, passwordHash)

	if err != nil {
		panic(err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   auth.Id,
		"rand": rand.Intn(100000),
	})

	tokenString, err := token.SignedString([]byte(EnvJWTSecret()))
	if err != nil {
		panic(err)
	}

	return &AuthResponse{
		Success: true,
		Token:   tokenString,
	}
}

// UpdateAuth implements dbHandler.
func (handler *dbHandlerImpl) UpdateAuth(auth AuthDTN) *AuthResponse {
	storedPasswordHash, err := handler.db.Query(`SELECT password_hash FROM auth WHERE lookup_hash = $1`, auth.LookupHash)
	if err != nil {
		log.Println(err)
		return &AuthResponse{
			Success: false,
			Token:   "",
		}
	}

	if storedPasswordHash.Next() {
		var passwordHash string
		err = storedPasswordHash.Scan(&passwordHash)
		if err != nil {
			log.Println(err)
			return &AuthResponse{
				Success: false,
				Token:   "",
			}
		}
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(auth.Password), EnvBcryptCost())
	if err != nil {
		panic(err)
	}

	_, err = handler.db.Exec(`UPDATE auth SET password_hash = $1 WHERE lookup_hash = $2`, newPasswordHash, auth.LookupHash)
	if err != nil {
		panic(err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   auth.Id,
		"rand": rand.Intn(100000),
	})

	tokenString, err := token.SignedString([]byte(EnvJWTSecret()))
	if err != nil {
		panic(err)
	}

	return &AuthResponse{
		Success: true,
		Token:   tokenString,
	}
}

// DeleteAuth implements dbHandler.
func (handler *dbHandlerImpl) DeleteAuth(lookupHash string) bool {

	_, err := handler.db.Exec(`DELETE FROM auth WHERE lookup_hash = $1`, lookupHash)
	if err != nil {
		log.Println(err)
		panic(err)
	}

	return true
}

// CompareAuth implements dbHandler.
func (handler *dbHandlerImpl) CompareAuth(auth AuthDT) bool {

	storedPasswordHashRow, err := handler.db.Query(`SELECT password_hash FROM auth WHERE lookup_hash = $1`, auth.LookupHash)
	if err != nil {
		log.Println(err)
		return false
	}

	var storedPasswordHash string

	if storedPasswordHashRow.Next() {
		err = storedPasswordHashRow.Scan(&storedPasswordHash)
		if err != nil {
			log.Println(err)
			return false
		}
	}

	return bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(auth.Password)) == nil
}

func NewDBHandler() dbHandler {

	postgresConfig := EnvPostgresConfig()

	postgresqlDbInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		postgresConfig.Host,
		postgresConfig.Port,
		postgresConfig.User,
		postgresConfig.Password,
		postgresConfig.DBName,
		// postgresConfig.SslMode,
	)

	db, err := sql.Open("postgres", postgresqlDbInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	return &dbHandlerImpl{db}
}

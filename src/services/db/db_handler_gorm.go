//go:build db_handler_gorm

package services_db

import (
	"embed"
	"fmt"
	"log"
	c "simple-micro-auth/src/configs"
	m "simple-micro-auth/src/models"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type dbHandlerImpl struct {
	db *gorm.DB
}

//go:embed migrations/*.sql
var embedMigrations embed.FS

type AuthModel struct {
	UserId       uuid.UUID `gorm:"type:uuid;primary_key"`
	PasswordHash string
}

func (AuthModel) TableName() string {
	return "auth"
}

func (handler *dbHandlerImpl) CreateCredentials(auth m.CredentialsDTO) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(auth.Password), c.EnvBcryptCost)

	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error creating password hash with bcrypt")
		return err
	}

	typedUserId, err := uuid.Parse(string(auth.UserId))
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error parsing user id to uuid")
		return err
	}

	authEntry := AuthModel{
		UserId:       typedUserId,
		PasswordHash: string(passwordHash),
	}

	err = handler.db.Create(&authEntry).Error

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
		UserId:   auth.UserId,
		Password: auth.OldPassword,
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

	typedUserId, err := uuid.Parse(string(auth.UserId))
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error parsing user id to uuid")
		return err
	}

	authEntry := AuthModel{
		UserId:       typedUserId,
		PasswordHash: string(passwordHash),
	}

	err = handler.db.Model(&authEntry).Update("PasswordHash", authEntry.PasswordHash).Error
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error updating password_hash in db while this user_id was found: %s", auth.UserId)
		return err
	}

	return err
}

func (handler *dbHandlerImpl) DeleteCredentials(userId m.UUID) error {

	typedUserId, err := uuid.Parse(string(userId))
	if err != nil {
		fmt.Println(err)
		return err
	}

	err = handler.db.Delete(&AuthModel{}, typedUserId).Error
	if err != nil {
		log.Println(err)
		err = fmt.Errorf("error deleting credentials from db")
		return err
	}

	return err
}

func (handler *dbHandlerImpl) VerifyCredentials(credentials m.CredentialsDTO) error {

	typedUserId, err := uuid.Parse(string(credentials.UserId))
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error parsing user id to uuid")
		return err
	}

	var storedPasswordHash string
	err = handler.db.Model(&AuthModel{}).Select("password_hash").Where("user_id = ?", typedUserId).Find(&storedPasswordHash).Error
	if err != nil {
		fmt.Println(err)
		err = fmt.Errorf("error reading password_hash from db")
		return err
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
	err := handler.db.Exec(`DELETE FROM auth`).Error

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

	db, err := gorm.Open(postgres.Open(postgresqlDbInfo), &gorm.Config{})
	if err != nil {
		log.Fatal("error opening db")
		log.Fatal("db connection string: ", postgresqlDbInfo)
		panic(err)
	}

	goose.SetBaseFS(embedMigrations)

	err = goose.SetDialect("postgres")
	if err != nil {
		log.Printf("error creating migrate instance: %v", err)
		panic(err)
	}

	nativeDB, err := db.DB()
	if err != nil {
		log.Printf("error getting native db instance: %v", err)
		panic(err)
	}

	err = goose.Up(nativeDB, "migrations")
	if err != nil {
		log.Fatal("could not run migrations")
		panic(err)
	} else {
		log.Println("migrations ran successfully")
	}

	return &dbHandlerImpl{db}
}

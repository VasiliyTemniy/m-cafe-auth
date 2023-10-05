package configs

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

var (
	EnvJWTSecret          string
	EnvJWTExpirationHours int
	EnvBcryptCost         int
	EnvPort               string
	EnvPostgresConfig     PostgresConfig
)

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SslMode  string
}

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	EnvJWTSecret = os.Getenv("JWT_SECRET")
	EnvJWTExpirationHours, err = strconv.Atoi(os.Getenv("JWT_EXPIRATION_HOURS"))
	if err != nil {
		EnvJWTExpirationHours = 24
	}
	EnvBcryptCost, err = strconv.Atoi(os.Getenv("BCRYPT_COST"))
	if err != nil {
		EnvBcryptCost = 10
	}
	EnvPort = os.Getenv("PORT")

	EnvPostgresConfig = getEnvPostgresConfig()

}

func getEnvPostgresConfig() PostgresConfig {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	var postgresConfig PostgresConfig

	postgresConfig.Host = os.Getenv("DATABASE_HOST")
	postgresConfig.Port = os.Getenv("DATABASE_PORT")
	postgresConfig.User = os.Getenv("DATABASE_USER")
	postgresConfig.Password = os.Getenv("DATABASE_PASSWORD")
	postgresConfig.SslMode = os.Getenv("DATABASE_SSLMODE")

	env := os.Getenv("GO_ENV")
	if env == "test" {
		postgresConfig.DBName = os.Getenv("TEST_DATABASE_DBNAME")
	} else {
		postgresConfig.DBName = os.Getenv("DATABASE_DBNAME")
	}

	return postgresConfig
}

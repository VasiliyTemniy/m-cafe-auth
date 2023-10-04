package configs

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SslMode  string
}

func EnvPostgresConfig() PostgresConfig {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	var postgresConfig PostgresConfig

	postgresConfig.Host = os.Getenv("DATABASE_HOST")
	postgresConfig.Port = os.Getenv("DATABASE_PORT")
	postgresConfig.User = os.Getenv("DATABASE_USER")
	postgresConfig.Password = os.Getenv("DATABASE_PASSWORD")
	postgresConfig.SslMode = os.Getenv("DATABASE_SSL_MODE")

	env := os.Getenv("GO_ENV")
	if env == "test" {
		postgresConfig.DBName = os.Getenv("TEST_DATABASE_DBNAME")
	} else {
		postgresConfig.DBName = os.Getenv("DATABASE_DBNAME")
	}

	return postgresConfig
}

func EnvBcryptCost() int {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	env := os.Getenv("BCRYPT_COST")
	if env == "" {
		return 10
	}

	cost, err := strconv.Atoi(env)
	if err != nil {
		panic(err)
	}

	return cost
}

func EnvJWTSecret() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	env := os.Getenv("JWT_SECRET")
	if env == "" {
		panic("JWT_SECRET must be set")
	}

	return env
}

func EnvPort() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	env := os.Getenv("PORT")
	if env == "" {
		return "4006"
	}

	return env
}

package configs

import (
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

var (
	EnvDockerized     string
	EnvJWTExpiration  time.Duration
	EnvBcryptCost     int
	EnvPort           string
	EnvPostgresConfig PostgresConfig
)

const projectDirName = "simple-micro-auth"

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SslMode  string
}

func init() {

	var err error

	EnvDockerized = os.Getenv("DOCKERIZED")

	if EnvDockerized != "true" {
		err = loadEnv()
		if err != nil {
			log.Fatal(err)
		}
	}

	env := os.Getenv("GO_ENV")

	if env == "test" {
		EnvJWTExpiration, err = time.ParseDuration(os.Getenv("TEST_JWT_TTL"))
		if err != nil {
			EnvJWTExpiration, _ = time.ParseDuration("24h")
		}
		EnvBcryptCost, err = strconv.Atoi(os.Getenv("TEST_BCRYPT_COST"))
		if err != nil {
			EnvBcryptCost = 10
		}
		EnvPort = os.Getenv("PORT")

		EnvPostgresConfig.Host = os.Getenv("TEST_DATABASE_HOST")
		EnvPostgresConfig.Port = os.Getenv("TEST_DATABASE_PORT")
		EnvPostgresConfig.User = os.Getenv("TEST_DATABASE_USER")
		EnvPostgresConfig.Password = os.Getenv("TEST_DATABASE_PASSWORD")
		EnvPostgresConfig.SslMode = os.Getenv("TEST_DATABASE_SSLMODE")
		EnvPostgresConfig.DBName = os.Getenv("TEST_DATABASE_DBNAME")

	} else {
		EnvJWTExpiration, err = time.ParseDuration(os.Getenv("JWT_TTL"))
		if err != nil {
			EnvJWTExpiration, _ = time.ParseDuration("24h")
		}
		EnvBcryptCost, err = strconv.Atoi(os.Getenv("BCRYPT_COST"))
		if err != nil {
			EnvBcryptCost = 10
		}
		EnvPort = os.Getenv("PORT")

		EnvPostgresConfig.Host = os.Getenv("DATABASE_HOST")
		EnvPostgresConfig.Port = os.Getenv("DATABASE_PORT")
		EnvPostgresConfig.User = os.Getenv("DATABASE_USER")
		EnvPostgresConfig.Password = os.Getenv("DATABASE_PASSWORD")
		EnvPostgresConfig.SslMode = os.Getenv("DATABASE_SSLMODE")
		EnvPostgresConfig.DBName = os.Getenv("DATABASE_DBNAME")
	}
}

func loadEnv() error {
	projectName := regexp.MustCompile(`^(.*` + projectDirName + `)`)
	currentWorkDirectory, _ := os.Getwd()
	rootPath := projectName.Find([]byte(currentWorkDirectory))

	err := godotenv.Load(string(rootPath) + `/.env`)

	return err
}

package services_db

import (
	m "simple-micro-auth/src/models"
)

type dbHandler interface {
	CreateCredentials(auth m.CredentialsDTO) error
	UpdateCredentials(auth m.CredentialsDTOUpdate) error
	DeleteCredentials(userId m.UUID) error
	VerifyCredentials(credentials m.CredentialsDTO) error
	FlushDB() error
}

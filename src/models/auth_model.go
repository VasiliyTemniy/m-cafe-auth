package models

type AuthDTO struct {
	Id         int64
	LookupHash string
	Password   string
}

type AuthDTOUpdate struct {
	Id          int64
	LookupHash  string
	OldPassword string
	NewPassword string
}

type CredentialsDTO struct {
	LookupHash string
	Password   string
}

type CredentialsDTOUpdate struct {
	LookupHash  string
	OldPassword string
	NewPassword string
}

type AuthResponse struct {
	Id    int64
	Token string
	Error string
}

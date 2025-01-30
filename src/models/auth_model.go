package models

type UUID string

type AuthDTO struct {
	UserId   UUID
	AppId    UUID
	Password string
}

type AuthDTOUpdate struct {
	UserId      UUID
	AppId       UUID
	OldPassword string
	NewPassword string
}

type CredentialsDTO struct {
	UserId   UUID
	AppId    UUID
	Password string
}

type CredentialsDTOUpdate struct {
	UserId	   	UUID
	AppId       UUID
	OldPassword string
	NewPassword string
}

type AuthResponse struct {
	UserId UUID
	Token	 string
	Error  string
}

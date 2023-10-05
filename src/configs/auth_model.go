package configs

type AuthDTOUpdate struct {
	Id          int64
	LookupHash  string
	OldPassword string
	NewPassword string
}

type AuthDTO struct {
	Id         int64
	LookupHash string
	Password   string
}

type AuthResponse struct {
	Id    int64
	Token string
	Error string
}

package configs

type AuthDT struct {
	LookupHash string
	Password   string
}

type AuthDTN struct {
	Id         int64
	LookupHash string
	Password   string
}

type AuthResponse struct {
	Success bool
	Token   string
}

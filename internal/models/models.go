package models

// GUID, Refresh Token Hash (RTH), RT expiration time (Unix timestamp), Access Token Hash
type RTHdoc struct {
	GUID  string
	RTH   string
	RTexp int64
	ATSH  string
}

type User struct {
	GUID string `json:"GUID"`
}

type TokensReplacement struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

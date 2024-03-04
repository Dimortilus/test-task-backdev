package models

// Refresh Token Hash, GUID, exp (Unix timestamp)
type RTHdoc struct {
	GUID string
	RTH  string
	Exp  int64
}

type User struct {
	GUID string `json:"GUID"`
}

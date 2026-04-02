package model

type Discover struct {
	AuthUrl string `json:"auth_url"`
	TokenUrl string `json:"token_url"`
	LogoutUrl string `json:"logout_url"`
	ClientID string `json:"client_id"`
}

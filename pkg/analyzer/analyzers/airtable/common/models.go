package common

type AirtableUserInfo struct {
	ID     string   `json:"id"`
	Email  *string  `json:"email,omitempty"`
	Scopes []string `json:"scopes"`
}

type AirtableBases struct {
	Bases []struct {
		ID     string  `json:"id"`
		Name   string  `json:"name"`
		Schema *Schema `json:"schema,omitempty"`
	} `json:"bases"`
}

type Schema struct {
	Tables []AirtableEntity `json:"tables"`
}

type AirtableEntity struct {
	ID string `json:"id"`
}

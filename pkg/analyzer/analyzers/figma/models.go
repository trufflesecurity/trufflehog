package figma

type ScopeValidationResult struct {
	Status ScopeStatus
	Scopes []Scope
}

type UserInfo struct {
	ID     string `json:"id"`
	Handle string `json:"handle"`
	ImgURL string `json:"img_url"`
	Email  string `json:"email"`
}

type SecretInfo struct {
	UserInfo UserInfo
	Scopes   map[Scope]ScopeStatus
}

type APIErrorResponse struct {
	Status  int    `json:"status"`
	Err     string `json:"err"`
	Message string `json:"message"`
	I18n    struct {
		FallBackText string `json:"fallback_text"`
	} `json:"i18n"`
}

type Endpoint struct {
	URL                          string
	Method                       string
	ExpectedResponseWithScope    APIErrorResponse
	ExpectedResponseWithoutScope APIErrorResponse
}

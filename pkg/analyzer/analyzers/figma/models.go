package figma

type scopeValidationResult struct {
	Status ScopeStatus
	Scopes []Scope
}

type userInfo struct {
	ID     string `json:"id"`
	Handle string `json:"handle"`
	ImgURL string `json:"img_url"`
	Email  string `json:"email"`
}

type secretInfo struct {
	UserInfo userInfo
	Scopes   map[Scope]ScopeStatus
}

type apiErrorResponse struct {
	Status  int    `json:"status"`
	Err     string `json:"err"`
	Message string `json:"message"`
}

type endpoint struct {
	URL                          string           `json:"url"`
	Method                       string           `json:"method"`
	ExpectedResponseWithScope    apiErrorResponse `json:"expected_response_with_scope"`
	ExpectedResponseWithoutScope apiErrorResponse `json:"expected_response_without_scope"`
}

package figma

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

type endpoint struct {
	URL                            string `json:"url"`
	Method                         string `json:"method"`
	ExpectedStatusCodeWithScope    int    `json:"expected_status_code_with_scope"`
	ExpectedStatusCodeWithoutScope int    `json:"expected_status_code_without_scope"`
}

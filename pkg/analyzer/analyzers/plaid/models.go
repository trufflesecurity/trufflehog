package plaid

type account struct {
	AccountID    string `json:"account_id"`
	Name         string `json:"name"`
	OfficialName string `json:"official_name"`
	Subtype      string `json:"subtype"`
	Type         string `json:"type"`
}

type item struct {
	Products []string `json:"products"`
}

type accountsResponse struct {
	Accounts  []account `json:"accounts"`
	Item      item      `json:"item"`
	RequestID string    `json:"request_id"`
}

type secretInfo struct {
	Accounts    []account
	Products    []string
	Environment string
}

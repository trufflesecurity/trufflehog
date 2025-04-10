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
	ItemID   string   `json:"item_id"`
}

type accountsResponse struct {
	Accounts []account `json:"accounts"`
	Item     item      `json:"item"`
}

type secretInfo struct {
	Item        item
	Accounts    []account
	Environment string
}

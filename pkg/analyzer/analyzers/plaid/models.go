package plaid

type balances struct {
	Available              float64 `json:"available"`
	Current                float64 `json:"current"`
	IsoCurrencyCode        string  `json:"iso_currency_code"`
	Limit                  float64 `json:"limit"`
	UnofficialCurrencyCode string  `json:"unofficial_currency_code"`
}

type owner struct {
	Addresses []struct {
		Data struct {
			City       string `json:"city"`
			Country    string `json:"country"`
			PostalCode string `json:"postal_code"`
			Region     string `json:"region"`
			Street     string `json:"street"`
		} `json:"data"`
		Primary bool `json:"primary"`
	} `json:"addresses"`
	Emails []struct {
		Data    string `json:"data"`
		Primary bool   `json:"primary"`
		Type    string `json:"type"`
	} `json:"emails"`
	Names        []string `json:"names"`
	PhoneNumbers []struct {
		Data    string `json:"data"`
		Primary bool   `json:"primary"`
		Type    string `json:"type"`
	} `json:"phone_numbers"`
}

type account struct {
	AccountID    string   `json:"account_id"`
	Balances     balances `json:"balances"`
	Mask         string   `json:"mask"`
	Name         string   `json:"name"`
	OfficialName string   `json:"official_name"`
	Owners       []owner  `json:"owners"`
	Subtype      string   `json:"subtype"`
	Type         string   `json:"type"`
}

type item struct {
	AuthMethod            string   `json:"auth_method"`
	AvailableProducts     []string `json:"available_products"`
	BilledProducts        []string `json:"billed_products"`
	ConsentExpirationTime string   `json:"consent_expiration_time"`
	InstitutionID         string   `json:"institution_id"`
	ItemID                string   `json:"item_id"`
	Webhook               string   `json:"webhook"`
	Products              []string `json:"products"`
	UpdateType            string   `json:"update_type"`
}

type accountsResponse struct {
	Accounts  []account `json:"accounts"`
	Item      item      `json:"item"`
	RequestID string    `json:"request_id"`
}

type secretInfo struct {
	Accounts []account
	Products []string
}

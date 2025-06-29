package coinbase

// Product API Resources

type account struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	Currency          string `json:"currency"`
	AvailableBalance  amount `json:"available_balance"`
	Default           bool   `json:"default"`
	Active            bool   `json:"active"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
	DeletedAt         string `json:"deleted_at"`
	Type              string `json:"type"`
	Ready             bool   `json:"ready"`
	Hold              amount `json:"hold"`
	RetailPortfolioID string `json:"retail_portfolio_id"`
	Platform          string `json:"platform"`
}

type amount struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

type order struct {
	OrderID               string `json:"order_id"`
	ProductID             string `json:"product_id"`
	UserID                string `json:"user_id"`
	Side                  string `json:"side"`
	ClientOrderID         string `json:"client_order_id"`
	Status                string `json:"status"`
	TimeInForce           string `json:"time_in_force"`
	CreatedTime           string `json:"created_time"`
	CompletionPercentage  string `json:"completion_percentage"`
	FilledSize            string `json:"filled_size"`
	AverageFilledPrice    string `json:"average_filled_price"`
	Fee                   string `json:"fee"`
	NumberOfFills         string `json:"number_of_fills"`
	FilledValue           string `json:"filled_value"`
	PendingCancel         bool   `json:"pending_cancel"`
	SizeInQuote           bool   `json:"size_in_quote"`
	TotalFees             string `json:"total_fees"`
	SizeInclusiveOfFees   bool   `json:"size_inclusive_of_fees"`
	TotalValueAfterFees   string `json:"total_value_after_fees"`
	TriggerStatus         string `json:"trigger_status"`
	OrderType             string `json:"order_type"`
	RejectReason          string `json:"reject_reason"`
	Settled               bool   `json:"settled"`
	ProductType           string `json:"product_type"`
	RejectMessage         string `json:"reject_message"`
	CancelMessage         string `json:"cancel_message"`
	OrderPlacementSource  string `json:"order_placement_source"`
	OutstandingHoldAmount string `json:"outstanding_hold_amount"`
	IsLiquidation         bool   `json:"is_liquidation"`
	LastFillTime          string `json:"last_fill_time"`
	Leverage              string `json:"leverage"`
	MarginType            string `json:"margin_type"`
	RetailPortfolioID     string `json:"retail_portfolio_id"`
	OriginatingOrderID    string `json:"originating_order_id"`
	AttachedOrderID       string `json:"attached_order_id"`
}

type portfolio struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	Type    string `json:"type"`
	Deleted bool   `json:"deleted"`
}

type paymentMethod struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Currency      string `json:"currency"`
	Verified      bool   `json:"verified"`
	AllowBuy      bool   `json:"allow_buy"`
	AllowSell     bool   `json:"allow_sell"`
	AllowDeposit  bool   `json:"allow_deposit"`
	AllowWithdraw bool   `json:"allow_withdraw"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// CDP API Resources

type wallet struct {
	ID                 string     `json:"id"`
	NetworkID          string     `json:"network_id"`
	DefaultAddress     address    `json:"default_address"`
	FeatureSet         featureSet `json:"feature_set"`
	ServerSignerStatus string     `json:"server_signer_status"`
}

type featureSet struct {
	Faucet       bool `json:"faucet"`
	ServerSigner bool `json:"server_signer"`
	Transfer     bool `json:"transfer"`
	Trade        bool `json:"trade"`
	Stake        bool `json:"stake"`
	GaslessSend  bool `json:"gasless_send"`
}

type address struct {
	WalletID  string `json:"wallet_id"`
	NetworkID string `json:"network_id"`
	PublicKey string `json:"public_key"`
	AddressID string `json:"address_id"`
}

// API Response Object Structs

type keyPermissionsResponse struct {
	CanView     bool `json:"can_view"`
	CanTrade    bool `json:"can_trade"`
	CanTransfer bool `json:"can_transfer"`
}

type accountsResponse struct {
	Accounts []account `json:"accounts"`
	HasNext  bool      `json:"has_next"`
	Cursor   string    `json:"cursor"`
}

type ordersResponse struct {
	Orders  []order `json:"orders"`
	HasNext bool    `json:"has_next"`
	Cursor  string  `json:"cursor"`
}

type portfoliosResponse struct {
	Portfolios []portfolio `json:"portfolios"`
}

type paymentMethodsResponse struct {
	PaymentMethods []paymentMethod `json:"payment_methods"`
}

type walletsResponse struct {
	Data       []wallet `json:"data"`
	HasMore    bool     `json:"has_more"`
	NextPage   string   `json:"next_page"`
	TotalCount int      `json:"total_count"`
}

type addressesResponse struct {
	Data       []address `json:"data"`
	HasMore    bool      `json:"has_more"`
	NextPage   string    `json:"next_page"`
	TotalCount int       `json:"total_count"`
}

// Secret Information struct

type secretInfo struct {
	Accounts       []account
	Orders         []order
	Portfolios     []portfolio
	PaymentMethods []paymentMethod
	Wallets        []wallet
	Addresses      []address
	Permissions    map[Permission]struct{}
}

func (info *secretInfo) addPermission(perm Permission) {
	if info.Permissions == nil {
		info.Permissions = map[Permission]struct{}{}
	}
	info.Permissions[perm] = struct{}{}
}

func (info *secretInfo) hasPermission(permission string) bool {
	perm, err := PermissionFromString(permission)
	if err != nil {
		return false
	}
	_, ok := info.Permissions[perm]
	return ok
}

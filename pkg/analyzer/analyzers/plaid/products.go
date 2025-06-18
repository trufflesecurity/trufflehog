package plaid

type plaidProduct struct {
	Name            string
	DisplayName     string
	Description     string
	PermissionLevel Permission
}

type Product int

const (
	Assets Product = iota
	Auth
	Balance
	BalancePlus
	Beacon
	CraBaseReport
	CraIncomeInsights
	CraPartnerInsights
	CraNetworkInsights
	CraCashflowInsights
	CreditDetails
	Employment
	Identity
	IdentityMatch
	IdentityVerification
	Income
	IncomeVerification
	Investments
	InvestmentsAuth
	Layer
	Liabilities
	PayByBank
	PaymentInitiation
	ProcessorPayments
	ProcessorIdentity
	Profile
	RecurringTransactions
	Signal
	StandingOrders
	Statements
	Transactions
	TransactionsRefresh
	Transfer
)

var plaidProducts = map[Product]plaidProduct{
	Assets: {
		Name:            "assets",
		DisplayName:     "Assets",
		Description:     "Request, retrieve and share detailed reports of financial assets and account history",
		PermissionLevel: Write,
	},
	Auth: {
		Name:            "auth",
		DisplayName:     "Auth",
		Description:     "Retrieve account and routing numbers",
		PermissionLevel: Read,
	},
	Balance: {
		Name:            "balance",
		DisplayName:     "Balance",
		Description:     "Check current and available account balance in real time",
		PermissionLevel: Read,
	},
	BalancePlus: {
		Name:            "balance_plus",
		DisplayName:     "Balance Plus",
		Description:     "Estimate projected balances and financial runway",
		PermissionLevel: Read,
	},
	Beacon: {
		Name:            "beacon",
		DisplayName:     "Beacon",
		Description:     "Generate risk insights and fraud signals based on user account behavior",
		PermissionLevel: Write,
	},
	CraBaseReport: {
		Name:            "cra_base_report",
		DisplayName:     "CRA Base Report",
		Description:     "Generate a standardized financial report",
		PermissionLevel: Write,
	},
	CraIncomeInsights: {
		Name:            "cra_income_insights",
		DisplayName:     "CRA Income Insights",
		Description:     "Analyze income trends and consistency",
		PermissionLevel: Write,
	},
	CraPartnerInsights: {
		Name:            "cra_partner_insights",
		DisplayName:     "CRA Partner Insights",
		Description:     "Access custom insights",
		PermissionLevel: Write,
	},
	CraNetworkInsights: {
		Name:            "cra_network_insights",
		DisplayName:     "CRA Network Insights",
		Description:     "View analytics and performance benchmarks",
		PermissionLevel: Write,
	},
	CraCashflowInsights: {
		Name:            "cra_cashflow_insights",
		DisplayName:     "CRA Cashflow Insights",
		Description:     "Evaluate cash flow behavior including recurring income and expenses",
		PermissionLevel: Write,
	},
	CreditDetails: {
		Name:            "credit_details",
		DisplayName:     "Credit Details",
		Description:     "Access credit account usage, limits, and repayment history",
		PermissionLevel: Read,
	},
	Employment: {
		Name:            "employment",
		DisplayName:     "Employment",
		Description:     "Retrieve current employment status and employer details",
		PermissionLevel: Read,
	},
	Identity: {
		Name:            "identity",
		DisplayName:     "Identity",
		Description:     "Access personal identity information like name, phone, address, and email",
		PermissionLevel: Read,
	},
	IdentityMatch: {
		Name:            "identity_match",
		DisplayName:     "Identity Match",
		Description:     "Match user-provided identity details against institution records",
		PermissionLevel: Read,
	},
	IdentityVerification: {
		Name:            "identity_verification",
		DisplayName:     "Identity Verification",
		Description:     "Verify user identity through government documents and identity data sources",
		PermissionLevel: Write,
	},
	Income: {
		Name:            "income",
		DisplayName:     "Income",
		Description:     "Analyze income patterns based on transaction history",
		PermissionLevel: Write,
	},
	IncomeVerification: {
		Name:            "income_verification",
		DisplayName:     "Income Verification",
		Description:     "Verify income through paystubs, payroll data, or bank information",
		PermissionLevel: Write,
	},
	Investments: {
		Name:            "investments",
		DisplayName:     "Investments",
		Description:     "Retrieve holdings, balances, and historical investment transactions",
		PermissionLevel: Read,
	},
	InvestmentsAuth: {
		Name:            "investments_auth",
		DisplayName:     "Investments Auth",
		Description:     "Retrieve account and routing numbers for investment accounts",
		PermissionLevel: Read,
	},
	Layer: {
		Name:            "layer",
		DisplayName:     "Layer",
		Description:     "Use a simplified onboarding experience for linking financial accounts",
		PermissionLevel: Read,
	},
	Liabilities: {
		Name:            "liabilities",
		DisplayName:     "Liabilities",
		Description:     "Access detailed information about loans, credit cards, and other liabilities",
		PermissionLevel: Write,
	},
	PayByBank: {
		Name:            "pay_by_bank",
		DisplayName:     "Pay By Bank",
		Description:     "Initiate payments directly from the user's bank account",
		PermissionLevel: Write,
	},
	PaymentInitiation: {
		Name:            "payment_initiation",
		DisplayName:     "Payment Initiation",
		Description:     "Create and manage payment requests and track their status",
		PermissionLevel: Write,
	},
	ProcessorPayments: {
		Name:            "processor_payments",
		DisplayName:     "Processor Payments",
		Description:     "Send payment details securely to third-party processors",
		PermissionLevel: Write,
	},
	ProcessorIdentity: {
		Name:            "processor_identity",
		DisplayName:     "Processor Identity",
		Description:     "Share identity data with payment processors for verification",
		PermissionLevel: Read,
	},
	Profile: {
		Name:            "profile",
		DisplayName:     "Profile",
		Description:     "Access user profile data",
		PermissionLevel: Read,
	},
	RecurringTransactions: {
		Name:            "recurring_transactions",
		DisplayName:     "Recurring Transactions",
		Description:     "Identify and analyze recurring payments and subscriptions",
		PermissionLevel: Write,
	},
	Signal: {
		Name:            "signal",
		DisplayName:     "Signal",
		Description:     "Assess the likelihood of ACH returns",
		PermissionLevel: Read,
	},
	StandingOrders: {
		Name:            "standing_orders",
		DisplayName:     "Standing Orders",
		Description:     "View and manage recurring scheduled bank transfers",
		PermissionLevel: Write,
	},
	Statements: {
		Name:            "statements",
		DisplayName:     "Statements",
		Description:     "List and download historical bank statements in PDF format",
		PermissionLevel: Read,
	},
	Transactions: {
		Name:            "transactions",
		DisplayName:     "Transactions",
		Description:     "Retrieve, filter, and analyze categorized transaction history",
		PermissionLevel: Read,
	},
	TransactionsRefresh: {
		Name:            "transactions_refresh",
		DisplayName:     "Transactions Refresh",
		Description:     "Trigger a manual refresh to retrieve the latest transactions",
		PermissionLevel: Read,
	},
	Transfer: {
		Name:            "transfer",
		DisplayName:     "Transfer",
		Description:     "Initiate, manage, and track bank transfers",
		PermissionLevel: Write,
	},
}

func GetProductByName(name string) (plaidProduct, bool) {
	for _, product := range plaidProducts {
		if product.Name == name {
			return product, true
		}
	}
	return plaidProduct{}, false
}

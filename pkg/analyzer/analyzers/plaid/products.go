package plaid

type plaidProduct struct {
	Name        string
	Description string
}

var permissionToProduct = map[Permission]plaidProduct{
	Assets: {
		Name:        "Assets",
		Description: "Request, retrieve and share detailed reports of financial assets and account history",
	},
	Auth: {
		Name:        "Auth",
		Description: "Retrieve account and routing numbers",
	},
	Balance: {
		Name:        "Balance",
		Description: "Check current and available account balance in real time",
	},
	BalancePlus: {
		Name:        "Balance Plus",
		Description: "Estimate projected balances and financial runway",
	},
	Beacon: {
		Name:        "Beacon",
		Description: "Generate risk insights and fraud signals based on user account behavior",
	},
	CraBaseReport: {
		Name:        "CRA Base Report",
		Description: "Generate a standardized financial report",
	},
	CraIncomeInsights: {
		Name:        "CRA Income Insights",
		Description: "Analyze income trends and consistency",
	},
	CraPartnerInsights: {
		Name:        "CRA Partner Insights",
		Description: "Access custom insights",
	},
	CraNetworkInsights: {
		Name:        "CRA Network Insights",
		Description: "View analytics and performance benchmarks",
	},
	CraCashflowInsights: {
		Name:        "CRA Cashflow Insights",
		Description: "Evaluate cash flow behavior including recurring income and expenses",
	},
	CreditDetails: {
		Name:        "Credit Details",
		Description: "Access credit account usage, limits, and repayment history",
	},
	Employment: {
		Name:        "Employment",
		Description: "Retrieve current employment status and employer details",
	},
	Identity: {
		Name:        "Identity",
		Description: "Access personal identity information like name, phone, address, and email",
	},
	IdentityMatch: {
		Name:        "Identity Match",
		Description: "Match user-provided identity details against institution records",
	},
	IdentityVerification: {
		Name:        "Identity Verification",
		Description: "Verify user identity through government documents and identity data sources",
	},
	Income: {
		Name:        "Income",
		Description: "Analyze income patterns based on transaction history",
	},
	IncomeVerification: {
		Name:        "Income Verification",
		Description: "Verify income through paystubs, payroll data, or bank information",
	},
	Investments: {
		Name:        "Investments",
		Description: "Retrieve holdings, balances, and historical investment transactions",
	},
	InvestmentsAuth: {
		Name:        "Investments Auth",
		Description: "Retrieve account and routing numbers for investment accounts",
	},
	Layer: {
		Name:        "Layer",
		Description: "Use a simplified onboarding experience for linking financial accounts",
	},
	Liabilities: {
		Name:        "Liabilities",
		Description: "Access detailed information about loans, credit cards, and other liabilities",
	},
	PayByBank: {
		Name:        "Pay By Bank",
		Description: "Initiate payments directly from the user's bank account",
	},
	PaymentInitiation: {
		Name:        "Payment Initiation",
		Description: "Create and manage payment requests and track their status",
	},
	ProcessorPayments: {
		Name:        "Processor Payments",
		Description: "Send payment details securely to third-party processors",
	},
	ProcessorIdentity: {
		Name:        "Processor Identity",
		Description: "Share identity data with payment processors for verification",
	},
	Profile: {
		Name:        "Profile",
		Description: "Access user profile data",
	},
	RecurringTransactions: {
		Name:        "Recurring Transactions",
		Description: "Identify and analyze recurring payments and subscriptions",
	},
	Signal: {
		Name:        "Signal",
		Description: "Assess the likelihood of ACH returns",
	},
	StandingOrders: {
		Name:        "Standing Orders",
		Description: "View and manage recurring scheduled bank transfers",
	},
	Statements: {
		Name:        "Statements",
		Description: "List and download historical bank statements in PDF format",
	},
	Transactions: {
		Name:        "Transactions",
		Description: "Retrieve, filter, and analyze categorized transaction history",
	},
	TransactionsRefresh: {
		Name:        "Transactions Refresh",
		Description: "Trigger a manual refresh to retrieve the latest transactions",
	},
	Transfer: {
		Name:        "Transfer",
		Description: "Initiate, manage, and track bank transfers",
	},
}

// Code generated by go generate; DO NOT EDIT.
package plaid

import "errors"

type Permission int

const (
    Invalid Permission = iota
    Assets Permission = iota
    Auth Permission = iota
    Balance Permission = iota
    BalancePlus Permission = iota
    Beacon Permission = iota
    CraBaseReport Permission = iota
    CraIncomeInsights Permission = iota
    CraPartnerInsights Permission = iota
    CraNetworkInsights Permission = iota
    CraCashflowInsights Permission = iota
    CreditDetails Permission = iota
    Employment Permission = iota
    Identity Permission = iota
    IdentityMatch Permission = iota
    IdentityVerification Permission = iota
    Income Permission = iota
    IncomeVerification Permission = iota
    Investments Permission = iota
    InvestmentsAuth Permission = iota
    Layer Permission = iota
    Liabilities Permission = iota
    PayByBank Permission = iota
    PaymentInitiation Permission = iota
    ProcessorPayments Permission = iota
    ProcessorIdentity Permission = iota
    Profile Permission = iota
    RecurringTransactions Permission = iota
    Signal Permission = iota
    StandingOrders Permission = iota
    Statements Permission = iota
    Transactions Permission = iota
    TransactionsRefresh Permission = iota
    Transfer Permission = iota
)

var (
    PermissionStrings = map[Permission]string{
        Assets: "assets",
        Auth: "auth",
        Balance: "balance",
        BalancePlus: "balance_plus",
        Beacon: "beacon",
        CraBaseReport: "cra_base_report",
        CraIncomeInsights: "cra_income_insights",
        CraPartnerInsights: "cra_partner_insights",
        CraNetworkInsights: "cra_network_insights",
        CraCashflowInsights: "cra_cashflow_insights",
        CreditDetails: "credit_details",
        Employment: "employment",
        Identity: "identity",
        IdentityMatch: "identity_match",
        IdentityVerification: "identity_verification",
        Income: "income",
        IncomeVerification: "income_verification",
        Investments: "investments",
        InvestmentsAuth: "investments_auth",
        Layer: "layer",
        Liabilities: "liabilities",
        PayByBank: "pay_by_bank",
        PaymentInitiation: "payment_initiation",
        ProcessorPayments: "processor_payments",
        ProcessorIdentity: "processor_identity",
        Profile: "profile",
        RecurringTransactions: "recurring_transactions",
        Signal: "signal",
        StandingOrders: "standing_orders",
        Statements: "statements",
        Transactions: "transactions",
        TransactionsRefresh: "transactions_refresh",
        Transfer: "transfer",
    }

    StringToPermission = map[string]Permission{
        "assets": Assets,
        "auth": Auth,
        "balance": Balance,
        "balance_plus": BalancePlus,
        "beacon": Beacon,
        "cra_base_report": CraBaseReport,
        "cra_income_insights": CraIncomeInsights,
        "cra_partner_insights": CraPartnerInsights,
        "cra_network_insights": CraNetworkInsights,
        "cra_cashflow_insights": CraCashflowInsights,
        "credit_details": CreditDetails,
        "employment": Employment,
        "identity": Identity,
        "identity_match": IdentityMatch,
        "identity_verification": IdentityVerification,
        "income": Income,
        "income_verification": IncomeVerification,
        "investments": Investments,
        "investments_auth": InvestmentsAuth,
        "layer": Layer,
        "liabilities": Liabilities,
        "pay_by_bank": PayByBank,
        "payment_initiation": PaymentInitiation,
        "processor_payments": ProcessorPayments,
        "processor_identity": ProcessorIdentity,
        "profile": Profile,
        "recurring_transactions": RecurringTransactions,
        "signal": Signal,
        "standing_orders": StandingOrders,
        "statements": Statements,
        "transactions": Transactions,
        "transactions_refresh": TransactionsRefresh,
        "transfer": Transfer,
    }

    PermissionIDs = map[Permission]int{
        Assets: 1,
        Auth: 2,
        Balance: 3,
        BalancePlus: 4,
        Beacon: 5,
        CraBaseReport: 6,
        CraIncomeInsights: 7,
        CraPartnerInsights: 8,
        CraNetworkInsights: 9,
        CraCashflowInsights: 10,
        CreditDetails: 11,
        Employment: 12,
        Identity: 13,
        IdentityMatch: 14,
        IdentityVerification: 15,
        Income: 16,
        IncomeVerification: 17,
        Investments: 18,
        InvestmentsAuth: 19,
        Layer: 20,
        Liabilities: 21,
        PayByBank: 22,
        PaymentInitiation: 23,
        ProcessorPayments: 24,
        ProcessorIdentity: 25,
        Profile: 26,
        RecurringTransactions: 27,
        Signal: 28,
        StandingOrders: 29,
        Statements: 30,
        Transactions: 31,
        TransactionsRefresh: 32,
        Transfer: 33,
    }

    IdToPermission = map[int]Permission{
        1: Assets,
        2: Auth,
        3: Balance,
        4: BalancePlus,
        5: Beacon,
        6: CraBaseReport,
        7: CraIncomeInsights,
        8: CraPartnerInsights,
        9: CraNetworkInsights,
        10: CraCashflowInsights,
        11: CreditDetails,
        12: Employment,
        13: Identity,
        14: IdentityMatch,
        15: IdentityVerification,
        16: Income,
        17: IncomeVerification,
        18: Investments,
        19: InvestmentsAuth,
        20: Layer,
        21: Liabilities,
        22: PayByBank,
        23: PaymentInitiation,
        24: ProcessorPayments,
        25: ProcessorIdentity,
        26: Profile,
        27: RecurringTransactions,
        28: Signal,
        29: StandingOrders,
        30: Statements,
        31: Transactions,
        32: TransactionsRefresh,
        33: Transfer,
    }
)

// ToString converts a Permission enum to its string representation
func (p Permission) ToString() (string, error) {
    if str, ok := PermissionStrings[p]; ok {
        return str, nil
    }
    return "", errors.New("invalid permission")
}

// ToID converts a Permission enum to its ID
func (p Permission) ToID() (int, error) {
    if id, ok := PermissionIDs[p]; ok {
        return id, nil
    }
    return 0, errors.New("invalid permission")
}

// PermissionFromString converts a string representation to its Permission enum
func PermissionFromString(s string) (Permission, error) {
    if p, ok := StringToPermission[s]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission string")
}

// PermissionFromID converts an ID to its Permission enum
func PermissionFromID(id int) (Permission, error) {
    if p, ok := IdToPermission[id]; ok {
        return p, nil
    }
    return 0, errors.New("invalid permission ID")
}

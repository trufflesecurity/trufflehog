//go:build !no_tui

package square

var permissions_slice = []map[string]map[string][]string{
	{
		"Bank Accounts": {
			"GetBankAccount":       []string{"BANK_ACCOUNTS_READ"},
			"ListBankAccounts":     []string{"BANK_ACCOUNTS_READ"},
			"GetBankAccountByV1Id": []string{"BANK_ACCOUNTS_READ"},
		},
	},
	{
		"Bookings": {
			"CreateBooking (buyer-level)":       []string{"APPOINTMENTS_WRITE"},
			"CreateBooking (seller-level)":      []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
			"SearchAvailability (buyer-level)":  []string{"APPOINTMENTS_READ"},
			"SearchAvailability (seller-level)": []string{"APPOINTMENTS_READ", "APPOINTMENTS_ALL_READ"},
			"RetrieveBusinessBookingProfile":    []string{"APPOINTMENTS_BUSINESS_SETTINGS_READ"},
			"ListTeamMemberBookingProfiles":     []string{"APPOINTMENTS_BUSINESS_SETTINGS_READ"},
			"RetrieveTeamMemberBookingProfile":  []string{"APPOINTMENTS_BUSINESS_SETTINGS_READ"},
			"ListBookings (buyer-level)":        []string{"APPOINTMENTS_READ"},
			"ListBookings (seller-level)":       []string{"APPOINTMENTS_READ", "APPOINTMENTS_ALL_READ"},
			"RetrieveBooking (buyer-level)":     []string{"APPOINTMENTS_READ"},
			"RetrieveBooking (seller-level)":    []string{"APPOINTMENTS_READ", "APPOINTMENTS_ALL_READ"},
			"UpdateBooking (buyer-level)":       []string{"APPOINTMENTS_WRITE"},
			"UpdateBooking (seller-level)":      []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
			"CancelBooking (buyer-level)":       []string{"APPOINTMENTS_WRITE"},
			"CancelBooking (seller-level)":      []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
		},
	},
	{
		"Booking Custom Attributes": {
			"CreateBookingCustomAttributeDefinition (buyer-level)":    []string{"APPOINTMENTS_WRITE"},
			"CreateBookingCustomAttributeDefinition (seller-level)":   []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
			"UpdateBookingCustomAttributeDefinition (buyer-level)":    []string{"APPOINTMENTS_WRITE"},
			"UpdateBookingCustomAttributeDefinition (seller-level)":   []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
			"ListBookingCustomAttributeDefinitions (buyer-level)":     []string{"APPOINTMENTS_READ"},
			"ListBookingCustomAttributeDefinitions (seller-level)":    []string{"APPOINTMENTS_READ", "APPOINTMENTS_ALL_READ"},
			"RetrieveBookingCustomAttributeDefinition (buyer-level)":  []string{"APPOINTMENTS_READ"},
			"RetrieveBookingCustomAttributeDefinition (seller-level)": []string{"APPOINTMENTS_READ", "APPOINTMENTS_ALL_READ"},
			"DeleteBookingCustomAttributeDefinition (buyer-level)":    []string{"APPOINTMENTS_WRITE"},
			"DeleteBookingCustomAttributeDefinition (seller-level)":   []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
			"UpsertBookingCustomAttribute (buyer-level)":              []string{"APPOINTMENTS_WRITE"},
			"UpsertBookingCustomAttribute (seller-level)":             []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
			"BulkUpsertBookingCustomAttributes (buyer-level)":         []string{"APPOINTMENTS_WRITE"},
			"BulkUpsertBookingCustomAttributes (seller-level)":        []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
			"ListBookingCustomAttributes (buyer-level)":               []string{"APPOINTMENTS_READ"},
			"ListBookingCustomAttributes (seller-level)":              []string{"APPOINTMENTS_READ", "APPOINTMENTS_ALL_READ"},
			"RetrieveBookingCustomAttribute (buyer-level)":            []string{"APPOINTMENTS_READ"},
			"RetrieveBookingCustomAttribute (seller-level)":           []string{"APPOINTMENTS_READ", "APPOINTMENTS_ALL_READ"},
			"DeleteBookingCustomAttribute (buyer-level)":              []string{"APPOINTMENTS_WRITE"},
			"DeleteBookingCustomAttribute (seller-level)":             []string{"APPOINTMENTS_WRITE", "APPOINTMENTS_ALL_WRITE"},
		},
	},
	{
		"Cards": {
			"ListCards":    []string{"PAYMENTS_READ"},
			"CreateCard":   []string{"PAYMENTS_WRITE"},
			"RetrieveCard": []string{"PAYMENTS_READ"},
			"DisableCard":  []string{"PAYMENTS_WRITE"},
		},
	},
	{
		"Cash Drawer Shifts": {
			"ListCashDrawerShifts":      []string{"CASH_DRAWER_READ"},
			"ListCashDrawerShiftEvents": []string{"CASH_DRAWER_READ"},
			"RetrieveCashDrawerShift":   []string{"CASH_DRAWER_READ"},
		},
	},
	{
		"Catalog": {
			"BatchDeleteCatalogObjects":   []string{"ITEMS_WRITE"},
			"BatchUpsertCatalogObjects":   []string{"ITEMS_WRITE"},
			"BatchRetrieveCatalogObjects": []string{"ITEMS_READ"},
			"CatalogInfo":                 []string{"ITEMS_READ"},
			"CreateCatalogImage":          []string{"ITEMS_WRITE"},
			"DeleteCatalogObject":         []string{"ITEMS_WRITE"},
			"ListCatalog":                 []string{"ITEMS_READ"},
			"RetrieveCatalogObject":       []string{"ITEMS_READ"},
			"SearchCatalogItems":          []string{"ITEMS_READ"},
			"SearchCatalogObjects":        []string{"ITEMS_READ"},
			"UpdateItemTaxes":             []string{"ITEMS_WRITE"},
			"UpdateItemModifierLists":     []string{"ITEMS_WRITE"},
			"UpsertCatalogObject":         []string{"ITEMS_WRITE"},
		},
	},
	{
		"Checkout": {
			"CreatePaymentLink": []string{"ORDERS_WRITE", "ORDERS_READ", "PAYMENTS_WRITE"},
		},
	},
	{
		"Customers": {
			"AddGroupToCustomer":              []string{"CUSTOMERS_WRITE"},
			"BulkCreateCustomers":             []string{"CUSTOMERS_WRITE"},
			"BulkDeleteCustomers":             []string{"CUSTOMERS_WRITE"},
			"BulkRetrieveCustomers":           []string{"CUSTOMERS_READ"},
			"BulkUpdateCustomers":             []string{"CUSTOMERS_WRITE"},
			"CreateCustomer":                  []string{"CUSTOMERS_WRITE"},
			"CreateCustomerCard (deprecated)": []string{"CUSTOMERS_WRITE"},
			"DeleteCustomer":                  []string{"CUSTOMERS_WRITE"},
			"DeleteCustomerCard (deprecated)": []string{"CUSTOMERS_WRITE"},
			"ListCustomers":                   []string{"CUSTOMERS_READ"},
			"RemoveGroupFromCustomer":         []string{"CUSTOMERS_WRITE"},
			"RetrieveCustomer":                []string{"CUSTOMERS_READ"},
			"SearchCustomers":                 []string{"CUSTOMERS_READ"},
			"UpdateCustomer":                  []string{"CUSTOMERS_WRITE"},
		},
	},
	{
		"Customer Custom Attributes": {
			"CreateCustomerCustomAttributeDefinition":   []string{"CUSTOMERS_WRITE"},
			"UpdateCustomerCustomAttributeDefinition":   []string{"CUSTOMERS_WRITE"},
			"ListCustomerCustomAttributeDefinitions":    []string{"CUSTOMERS_READ"},
			"RetrieveCustomerCustomAttributeDefinition": []string{"CUSTOMERS_READ"},
			"DeleteCustomerCustomAttributeDefinition":   []string{"CUSTOMERS_WRITE"},
			"UpsertCustomerCustomAttribute":             []string{"CUSTOMERS_WRITE"},
			"BulkUpsertCustomerCustomAttributes":        []string{"CUSTOMERS_WRITE"},
			"ListCustomerCustomAttributes":              []string{"CUSTOMERS_READ"},
			"RetrieveCustomerCustomAttribute":           []string{"CUSTOMERS_READ"},
			"DeleteCustomerCustomAttribute":             []string{"CUSTOMERS_WRITE"},
		},
	},
	{
		"Customer Groups": {
			"CreateCustomerGroup":   []string{"CUSTOMERS_WRITE"},
			"DeleteCustomerGroup":   []string{"CUSTOMERS_WRITE"},
			"ListCustomerGroups":    []string{"CUSTOMERS_READ"},
			"RetrieveCustomerGroup": []string{"CUSTOMERS_READ"},
			"UpdateCustomerGroup":   []string{"CUSTOMERS_WRITE"},
		},
	},
	{
		"Customer Segments": {
			"ListCustomerSegments":    []string{"CUSTOMERS_READ"},
			"RetrieveCustomerSegment": []string{"CUSTOMERS_READ"},
		},
	},
	{
		"Devices": {
			"CreateDeviceCode": []string{"DEVICE_CREDENTIAL_MANAGEMENT"},
			"GetDeviceCode":    []string{"DEVICE_CREDENTIAL_MANAGEMENT"},
			"ListDeviceCodes":  []string{"DEVICE_CREDENTIAL_MANAGEMENT"},
			"ListDevices":      []string{"DEVICES_READ"},
			"GetDevice":        []string{"DEVICES_READ"},
		},
	},
	{
		"Disputes": {
			"AcceptDispute":             []string{"DISPUTES_WRITE"},
			"CreateDisputeEvidenceFile": []string{"DISPUTES_WRITE"},
			"CreateDisputeEvidenceText": []string{"DISPUTES_WRITE"},
			"ListDisputeEvidence":       []string{"DISPUTES_READ"},
			"ListDisputes":              []string{"DISPUTES_READ"},
			"DeleteDisputeEvidence":     []string{"DISPUTES_WRITE"},
			"RetrieveDispute":           []string{"DISPUTES_READ"},
			"RetrieveDisputeEvidence":   []string{"DISPUTES_READ"},
			"SubmitEvidence":            []string{"DISPUTES_WRITE"},
		},
	},
	{
		"Employees": {
			"ListEmployees (deprecated)":    []string{"EMPLOYEES_READ"},
			"RetrieveEmployee (deprecated)": []string{"EMPLOYEES_READ"},
		},
	},
	{
		"Gift Cards": {
			"ListGiftCards":              []string{"GIFTCARDS_READ"},
			"CreateGiftCard":             []string{"GIFTCARDS_WRITE"},
			"RetrieveGiftCard":           []string{"GIFTCARDS_READ"},
			"RetrieveGiftCardFromGAN":    []string{"GIFTCARDS_READ"},
			"RetrieveGiftCardFromNonce":  []string{"GIFTCARDS_READ"},
			"LinkCustomerToGiftCard":     []string{"GIFTCARDS_WRITE"},
			"UnlinkCustomerFromGiftCard": []string{"GIFTCARDS_WRITE"},
		},
	},
	{
		"Gift Card Activities": {
			"ListGiftCardActivities": []string{"GIFTCARDS_READ"},
			"CreateGiftCardActivity": []string{"GIFTCARDS_WRITE"},
		},
	},
	{
		"Inventory": {
			"BatchChangeInventory":           []string{"INVENTORY_WRITE"},
			"BatchRetrieveInventoryCounts":   []string{"INVENTORY_READ"},
			"BatchRetrieveInventoryChanges":  []string{"INVENTORY_READ"},
			"RetrieveInventoryAdjustment":    []string{"INVENTORY_READ"},
			"RetrieveInventoryChanges":       []string{"INVENTORY_READ"},
			"RetrieveInventoryCount":         []string{"INVENTORY_READ"},
			"RetrieveInventoryPhysicalCount": []string{"INVENTORY_READ"},
		},
	},
	{
		"Invoices": {
			"CreateInvoice":           []string{"INVOICES_WRITE", "ORDERS_WRITE"},
			"PublishInvoice":          []string{"CUSTOMERS_READ", "PAYMENTS_WRITE", "INVOICES_WRITE", "ORDERS_WRITE"},
			"GetInvoice":              []string{"INVOICES_READ"},
			"ListInvoices":            []string{"INVOICES_READ"},
			"SearchInvoices":          []string{"INVOICES_READ"},
			"CreateInvoiceAttachment": []string{"INVOICES_WRITE", "ORDERS_WRITE"},
			"DeleteInvoiceAttachment": []string{"INVOICES_WRITE", "ORDERS_WRITE"},
			"UpdateInvoice":           []string{"INVOICES_WRITE", "ORDERS_WRITE"},
			"DeleteInvoice":           []string{"INVOICES_WRITE", "ORDERS_WRITE"},
			"CancelInvoice":           []string{"INVOICES_WRITE", "ORDERS_WRITE"},
		},
	},
	{
		"Labor": {
			"CreateBreakType":      []string{"TIMECARDS_SETTINGS_WRITE"},
			"CreateShift":          []string{"TIMECARDS_WRITE"},
			"DeleteBreakType":      []string{"TIMECARDS_SETTINGS_WRITE"},
			"DeleteShift":          []string{"TIMECARDS_WRITE"},
			"GetBreakType":         []string{"TIMECARDS_SETTINGS_READ"},
			"GetTeamMemberWage":    []string{"EMPLOYEES_READ"},
			"GetShift":             []string{"TIMECARDS_READ"},
			"ListBreakTypes":       []string{"TIMECARDS_SETTINGS_READ"},
			"ListTeamMemberWages":  []string{"EMPLOYEES_READ"},
			"ListWorkweekConfigs":  []string{"TIMECARDS_SETTINGS_READ"},
			"SearchShifts":         []string{"TIMECARDS_READ"},
			"UpdateShift":          []string{"TIMECARDS_WRITE", "TIMECARDS_READ"},
			"UpdateWorkweekConfig": []string{"TIMECARDS_SETTINGS_WRITE", "TIMECARDS_SETTINGS_READ"},
			"UpdateBreakType":      []string{"TIMECARDS_SETTINGS_WRITE", "TIMECARDS_SETTINGS_READ"},
		},
	},
	{
		"Locations": {
			"CreateLocation":   []string{"MERCHANT_PROFILE_WRITE"},
			"ListLocations":    []string{"MERCHANT_PROFILE_READ"},
			"RetrieveLocation": []string{"MERCHANT_PROFILE_READ"},
			"UpdateLocation":   []string{"MERCHANT_PROFILE_WRITE"},
		},
	},
	{
		"Location Custom Attributes": {
			"CreateLocationCustomAttributeDefinition":   []string{"MERCHANT_PROFILE_WRITE"},
			"UpdateLocationCustomAttributeDefinition":   []string{"MERCHANT_PROFILE_WRITE"},
			"ListLocationCustomAttributeDefinitions":    []string{"MERCHANT_PROFILE_READ"},
			"RetrieveLocationCustomAttributeDefinition": []string{"MERCHANT_PROFILE_READ"},
			"DeleteLocationCustomAttributeDefinition":   []string{"MERCHANT_PROFILE_WRITE"},
			"UpsertLocationCustomAttribute":             []string{"MERCHANT_PROFILE_WRITE"},
			"BulkUpsertLocationCustomAttributes":        []string{"MERCHANT_PROFILE_WRITE"},
			"ListLocationCustomAttributes":              []string{"MERCHANT_PROFILE_READ"},
			"RetrieveLocationCustomAttribute":           []string{"MERCHANT_PROFILE_READ"},
			"DeleteLocationCustomAttribute":             []string{"MERCHANT_PROFILE_WRITE"},
			"BulkDeleteLocationCustomAttributes":        []string{"MERCHANT_PROFILE_WRITE"},
		},
	},
	{
		"Loyalty": {
			"RetrieveLoyaltyProgram":           []string{"LOYALTY_READ"},
			"ListLoyaltyPrograms (deprecated)": []string{"LOYALTY_READ"},
			"CreateLoyaltyPromotion":           []string{"LOYALTY_WRITE"},
			"ListLoyaltyPromotions":            []string{"LOYALTY_READ"},
			"RetrieveLoyaltyPromotion":         []string{"LOYALTY_READ"},
			"CancelLoyaltyPromotion":           []string{"LOYALTY_WRITE"},
			"CreateLoyaltyAccount":             []string{"LOYALTY_WRITE"},
			"RetrieveLoyaltyAccount":           []string{"LOYALTY_READ"},
			"SearchLoyaltyAccounts":            []string{"LOYALTY_READ"},
			"AccumulateLoyaltyPoints":          []string{"LOYALTY_WRITE"},
			"AdjustLoyaltyPoints":              []string{"LOYALTY_WRITE"},
			"CalculateLoyaltyPoints":           []string{"LOYALTY_READ"},
			"CreateLoyaltyReward":              []string{"LOYALTY_WRITE"},
			"RedeemLoyaltyReward":              []string{"LOYALTY_WRITE"},
			"RetrieveLoyaltyReward":            []string{"LOYALTY_READ"},
			"SearchLoyaltyRewards":             []string{"LOYALTY_READ"},
			"DeleteLoyaltyReward":              []string{"LOYALTY_WRITE"},
			"SearchLoyaltyEvents":              []string{"LOYALTY_READ"},
		},
	},
	{
		"Merchants": {
			"ListMerchants":    []string{"MERCHANT_PROFILE_READ"},
			"RetrieveMerchant": []string{"MERCHANT_PROFILE_READ"},
		},
	},
	{
		"Merchant Custom Attributes": {
			"CreateMerchantCustomAttributeDefinition":   []string{"MERCHANT_PROFILE_WRITE"},
			"UpdateMerchantCustomAttributeDefinition":   []string{"MERCHANT_PROFILE_WRITE"},
			"ListMerchantCustomAttributeDefinitions":    []string{"MERCHANT_PROFILE_READ"},
			"RetrieveMerchantCustomAttributeDefinition": []string{"MERCHANT_PROFILE_READ"},
			"DeleteMerchantCustomAttributeDefinition":   []string{"MERCHANT_PROFILE_WRITE"},
			"UpsertMerchantCustomAttribute":             []string{"MERCHANT_PROFILE_WRITE"},
			"BulkUpsertMerchantCustomAttributes":        []string{"MERCHANT_PROFILE_WRITE"},
			"ListMerchantCustomAttributes":              []string{"MERCHANT_PROFILE_READ"},
			"RetrieveMerchantCustomAttribute":           []string{"MERCHANT_PROFILE_READ"},
			"DeleteMerchantCustomAttribute":             []string{"MERCHANT_PROFILE_WRITE"},
			"BulkDeleteMerchantCustomAttributes":        []string{"MERCHANT_PROFILE_WRITE"},
		},
	},
	{
		"Mobile Authorization": {
			"CreateMobileAuthorizationCode": []string{"PAYMENTS_WRITE_IN_PERSON"},
		},
	},
	{
		"Orders": {
			"CloneOrder":          []string{"ORDERS_WRITE"},
			"CreateOrder":         []string{"ORDERS_WRITE"},
			"BatchRetrieveOrders": []string{"ORDERS_READ"},
			"PayOrder":            []string{"ORDERS_WRITE", "PAYMENTS_WRITE"},
			"RetrieveOrder":       []string{"ORDERS_WRITE", "ORDERS_READ"},
			"SearchOrders":        []string{"ORDERS_READ"},
			"UpdateOrder":         []string{"ORDERS_WRITE"},
		},
	},
	{
		"Order Custom Attributes": {
			"CreateOrderCustomAttributeDefinition":   []string{"ORDERS_WRITE"},
			"UpdateOrderCustomAttributeDefinition":   []string{"ORDERS_WRITE"},
			"ListOrderCustomAttributeDefinitions":    []string{"ORDERS_READ"},
			"RetrieveOrderCustomAttributeDefinition": []string{"ORDERS_READ"},
			"DeleteOrderCustomAttributeDefinition":   []string{"ORDERS_WRITE"},
			"UpsertOrderCustomAttribute":             []string{"ORDERS_WRITE"},
			"BulkUpsertOrderCustomAttributes":        []string{"ORDERS_WRITE"},
			"ListOrderCustomAttributes":              []string{"ORDERS_READ"},
			"RetrieveOrderCustomAttribute":           []string{"ORDERS_READ"},
			"DeleteOrderCustomAttribute":             []string{"ORDERS_WRITE"},
			"BulkDeleteOrderCustomAttributes":        []string{"ORDERS_WRITE"},
		},
	},
	{
		"Payments and Refunds": {
			"CancelPayment":                 []string{"PAYMENTS_WRITE"},
			"CancelPaymentByIdempotencyKey": []string{"PAYMENTS_WRITE"},
			"CompletePayment":               []string{"PAYMENTS_WRITE"},
			"CreatePayment":                 []string{"PAYMENTS_WRITE", "PAYMENTS_WRITE_SHARED_ONFILE", "PAYMENTS_WRITE_ADDITIONAL_RECIPIENTS"},
			"GetPayment":                    []string{"PAYMENTS_READ"},
			"GetPaymentRefund":              []string{"PAYMENTS_READ"},
			"ListPayments":                  []string{"PAYMENTS_READ"},
			"ListPaymentRefunds":            []string{"PAYMENTS_READ"},
			"RefundPayment":                 []string{"PAYMENTS_WRITE", "PAYMENTS_WRITE_ADDITIONAL_RECIPIENTS"},
		},
	},
	{
		"Payouts": {
			"ListPayouts":       []string{"PAYOUTS_READ"},
			"GetPayout":         []string{"PAYOUTS_READ"},
			"ListPayoutEntries": []string{"PAYOUTS_READ"},
		},
	},
	{
		"Sites": {
			"ListSites": []string{"ONLINE_STORE_SITE_READ"},
		},
	},
	{
		"Snippets": {
			"UpsertSnippet":   []string{"ONLINE_STORE_SNIPPETS_WRITE"},
			"RetrieveSnippet": []string{"ONLINE_STORE_SNIPPETS_READ"},
			"DeleteSnippet":   []string{"ONLINE_STORE_SNIPPETS_WRITE"},
		},
	},
	{
		"Subscriptions": {
			"CreateSubscription":       []string{"CUSTOMERS_READ", "PAYMENTS_WRITE", "SUBSCRIPTIONS_WRITE", "ITEMS_READ", "ORDERS_WRITE", "INVOICES_WRITE"},
			"SearchSubscriptions":      []string{"SUBSCRIPTIONS_READ"},
			"RetrieveSubscription":     []string{"SUBSCRIPTIONS_READ"},
			"UpdateSubscription":       []string{"CUSTOMERS_READ", "PAYMENTS_WRITE", "SUBSCRIPTIONS_WRITE", "ITEMS_READ", "ORDERS_WRITE", "INVOICES_WRITE"},
			"CancelSubscription":       []string{"SUBSCRIPTIONS_WRITE"},
			"ListSubscriptionEvents":   []string{"SUBSCRIPTIONS_READ"},
			"ResumeSubscription":       []string{"CUSTOMERS_READ", "PAYMENTS_WRITE", "SUBSCRIPTIONS_WRITE", "ITEMS_READ", "ORDERS_WRITE", "INVOICES_WRITE"},
			"PauseSubscription":        []string{"CUSTOMERS_READ", "PAYMENTS_WRITE", "SUBSCRIPTIONS_WRITE", "ITEMS_READ", "ORDERS_WRITE", "INVOICES_WRITE"},
			"SwapPlan":                 []string{"CUSTOMERS_READ", "PAYMENTS_WRITE", "SUBSCRIPTIONS_WRITE", "ITEMS_READ", "ORDERS_WRITE", "INVOICES_WRITE"},
			"DeleteSubscriptionAction": []string{"SUBSCRIPTIONS_WRITE"},
		},
	},
	{
		"Team": {
			"BulkCreateTeamMembers": []string{"EMPLOYEES_WRITE"},
			"BulkUpdateTeamMembers": []string{"EMPLOYEES_WRITE"},
			"CreateTeamMember":      []string{"EMPLOYEES_WRITE"},
			"UpdateTeamMember":      []string{"EMPLOYEES_WRITE"},
			"RetrieveTeamMember":    []string{"EMPLOYEES_READ"},
			"RetrieveWageSetting":   []string{"EMPLOYEES_READ"},
			"SearchTeamMembers":     []string{"EMPLOYEES_READ"},
			"UpdateWageSetting":     []string{"EMPLOYEES_WRITE"},
		},
	},
	{
		"Terminal": {
			"CreateTerminalCheckout":  []string{"PAYMENTS_WRITE"},
			"CancelTerminalCheckout":  []string{"PAYMENTS_WRITE"},
			"GetTerminalCheckout":     []string{"PAYMENTS_READ"},
			"SearchTerminalCheckouts": []string{"PAYMENTS_READ"},
			"CreateTerminalRefund":    []string{"PAYMENTS_WRITE"},
			"CancelTerminalRefund":    []string{"PAYMENTS_WRITE"},
			"GetTerminalRefund":       []string{"PAYMENTS_READ"},
			"SearchTerminalRefunds":   []string{"PAYMENTS_READ"},
			"CreateTerminalAction":    []string{"PAYMENTS_WRITE"},
			"CancelTerminalAction":    []string{"PAYMENTS_WRITE"},
			"GetTerminalAction":       []string{"PAYMENTS_READ", "CUSTOMERS_READ"},
			"SearchTerminalAction":    []string{"PAYMENTS_READ"},
		},
	},
	{
		"Vendors": {
			"BulkCreateVendors":   []string{"VENDOR_WRITE"},
			"BulkRetrieveVendors": []string{"VENDOR_READ"},
			"BulkUpdateVendors":   []string{"VENDOR_WRITE"},
			"CreateVendor":        []string{"VENDOR_WRITE"},
			"SearchVendors":       []string{"VENDOR_READ"},
			"RetrieveVendor":      []string{"VENDOR_READ"},
			"UpdateVendors":       []string{"VENDOR_WRITE"},
		},
	},
}

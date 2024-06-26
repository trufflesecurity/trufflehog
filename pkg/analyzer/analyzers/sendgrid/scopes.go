package sendgrid

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
)

type SendgridScope struct {
	Category       string
	SubCategory    string
	Prefixes       []string // Prefixes for the scope
	Permissions    []string
	PermissionType analyzers.PermissionType
}

func (s *SendgridScope) AddPermission(permission string) {
	s.Permissions = append(s.Permissions, permission)
}

func (s *SendgridScope) RunTests() {
	if len(s.Permissions) == 0 {
		s.PermissionType = analyzers.NONE
		return
	}
	for _, permission := range s.Permissions {
		if strings.Contains(permission, ".read") {
			s.PermissionType = analyzers.READ
		} else {
			s.PermissionType = analyzers.READ_WRITE
			return
		}
	}
}

var SCOPES = []SendgridScope{
	// Billing
	{Category: "Billing", Prefixes: []string{"billing"}},
	// Restricted Access
	{Category: "API Keys", Prefixes: []string{"api_keys"}},
	{Category: "Alerts", Prefixes: []string{"alerts"}},
	{Category: "Category Management", Prefixes: []string{"categories"}},
	{Category: "Design Library", Prefixes: []string{"design_library"}},
	{Category: "Email Activity", Prefixes: []string{"messages"}},
	{Category: "Email Testing", Prefixes: []string{"email_testing"}},
	{Category: "IP Management", Prefixes: []string{"ips"}},
	{Category: "Inbound Parse", Prefixes: []string{"user.webhooks.parse.settings"}},
	{Category: "Mail Send", SubCategory: "Mail Send", Prefixes: []string{"mail.send"}},
	{Category: "Mail Send", SubCategory: "Scheduled Sends", Prefixes: []string{"user.scheduled_sends, mail.batch"}},
	{Category: "Mail Settings", SubCategory: "Address Allow List", Prefixes: []string{"mail_settings.address_whitelist"}},
	{Category: "Mail Settings", SubCategory: "BCC", Prefixes: []string{"mail_settings.bcc"}},
	{Category: "Mail Settings", SubCategory: "Bounce Purge", Prefixes: []string{"mail_settings.bounce_purge"}},
	{Category: "Mail Settings", SubCategory: "Event Notification", Prefixes: []string{"user.webhooks.event"}},
	{Category: "Mail Settings", SubCategory: "Footer", Prefixes: []string{"mail_settings.footer"}},
	{Category: "Mail Settings", SubCategory: "Forward Bounce", Prefixes: []string{"mail_settings.forward_bounce"}},
	{Category: "Mail Settings", SubCategory: "Forward Spam", Prefixes: []string{"mail_settings.forward_spam"}},
	{Category: "Mail Settings", SubCategory: "Legacy Email Template", Prefixes: []string{"mail_settings.template"}},
	{Category: "Mail Settings", SubCategory: "Plain Content", Prefixes: []string{"mail_settings.plain_content"}},
	{Category: "Mail Settings", SubCategory: "Spam Checker", Prefixes: []string{"mail_settings.spam_check"}},
	{Category: "Marketing", SubCategory: "Automation", Prefixes: []string{"marketing.automation"}},
	{Category: "Marketing", SubCategory: "Marketing", Prefixes: []string{"marketing.read"}},
	{Category: "Partners", Prefixes: []string{"partner_settings"}},
	{Category: "Recipients Data Erasure", Prefixes: []string{"recipients"}},
	{Category: "Security", Prefixes: []string{"access_settings"}},
	{Category: "Sender Authentication", Prefixes: []string{"whitelabel"}},
	{Category: "Stats", SubCategory: "Browser Stats", Prefixes: []string{"browsers"}},
	{Category: "Stats", SubCategory: "Category Stats", Prefixes: []string{"categories.stats"}},
	{Category: "Stats", SubCategory: "Email Clients and Devices", Prefixes: []string{"clients", "devices"}},
	{Category: "Stats", SubCategory: "Geographical", Prefixes: []string{"geo"}},
	{Category: "Stats", SubCategory: "Global Stats", Prefixes: []string{"stats.global"}},
	{Category: "Stats", SubCategory: "Mailbox Provider Stats", Prefixes: []string{"mailbox_providers"}},
	{Category: "Stats", SubCategory: "Parse Webhook", Prefixes: []string{"user.webhooks.parse.stats"}},
	{Category: "Stats", SubCategory: "Stats Overview", Prefixes: []string{"stats.read"}},
	{Category: "Stats", SubCategory: "Subuser Stats", Prefixes: []string{"subusers"}},
	{Category: "Suppressions", SubCategory: "Supressions", Prefixes: []string{"suppression"}},
	{Category: "Suppressions", SubCategory: "Unsubscribe Groups", Prefixes: []string{"asm.groups"}},
	{Category: "Template Engine", Prefixes: []string{"templates"}},
	{Category: "Tracking", SubCategory: "Click Tracking", Prefixes: []string{"tracking_settings.click"}},
	{Category: "Tracking", SubCategory: "Google Analytics", Prefixes: []string{"tracking_settings.google_analytics"}},
	{Category: "Tracking", SubCategory: "Open Tracking", Prefixes: []string{"tracking_settings.open"}},
	{Category: "Tracking", SubCategory: "Subscription Tracking", Prefixes: []string{"tracking_settings.subscription"}},
	{Category: "User Account", SubCategory: "Enforced TLS", Prefixes: []string{"user.settings.enforced_tls"}},
	{Category: "User Account", SubCategory: "Timezone", Prefixes: []string{"user.timezone"}},
	// Full Access Additional Categories
	{Category: "Suppressions", SubCategory: "Unsubscribe Group Suppressions", Prefixes: []string{"asm.groups.suppressions"}},
	{Category: "Suppressions", SubCategory: "Global Suppressions", Prefixes: []string{"asm.suppressions.global"}},
	{Category: "Credentials", Prefixes: []string{"credentials"}},
	{Category: "Mail Settings", Prefixes: []string{"mail_settings"}},
	{Category: "Signup", Prefixes: []string{"signup"}},
	{Category: "Suppressions", SubCategory: "Blocks", Prefixes: []string{"suppression.blocks"}},
	{Category: "Suppressions", SubCategory: "Bounces", Prefixes: []string{"suppression.bounces"}},
	{Category: "Suppressions", SubCategory: "Invalid Emails", Prefixes: []string{"suppression.invalid_emails"}},
	{Category: "Suppressions", SubCategory: "Spam Reports", Prefixes: []string{"suppression.spam_reports"}},
	{Category: "Suppressions", SubCategory: "Unsubscribes", Prefixes: []string{"suppression.unsubscribes"}},
	{Category: "Teammates", Prefixes: []string{"teammates"}},
	{Category: "Tracking", Prefixes: []string{"tracking_settings"}},
	{Category: "UI", Prefixes: []string{"ui"}},
	{Category: "User Account", SubCategory: "Account", Prefixes: []string{"user.account"}},
	{Category: "User Account", SubCategory: "Credits", Prefixes: []string{"user.credits"}},
	{Category: "User Account", SubCategory: "Email", Prefixes: []string{"user.email"}},
	{Category: "User Account", SubCategory: "Multifactor Authentication", Prefixes: []string{"user.multifactor_authentication"}},
	{Category: "User Account", SubCategory: "Password", Prefixes: []string{"user.password"}},
	{Category: "User Account", SubCategory: "Profile", Prefixes: []string{"user.profile"}},
	{Category: "User Account", SubCategory: "Username", Prefixes: []string{"user.username"}},
}

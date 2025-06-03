package ngrok

type ngrokResource struct {
	Name          string
	IsPaidFeature bool
}

var ngrokResources = []ngrokResource{
	{
		Name:          "Endpoints",
		IsPaidFeature: false,
	},
	{
		Name:          "Domains",
		IsPaidFeature: false,
	},
	{
		Name:          "Reserved Addresses",
		IsPaidFeature: true,
	},
	{
		Name:          "TLS Certificates",
		IsPaidFeature: true,
	},
	{
		Name:          "Kubernetes Operators",
		IsPaidFeature: true,
	},
	{
		Name:          "Certificate Authorities",
		IsPaidFeature: true,
	},
	{
		Name:          "IP Policies",
		IsPaidFeature: true,
	},
	{
		Name:          "Policy Rules",
		IsPaidFeature: true,
	},
	{
		Name:          "Application Users",
		IsPaidFeature: true,
	},
	{
		Name:          "Application Sessions",
		IsPaidFeature: true,
	},
	{
		Name:          "Agent Ingress",
		IsPaidFeature: true,
	},
	{
		Name:          "Tunnels",
		IsPaidFeature: false,
	},
	{
		Name:          "Tunnel Sessions",
		IsPaidFeature: false,
	},
	{
		Name:          "Event Destinations",
		IsPaidFeature: false,
	},
	{
		Name:          "Event Sources",
		IsPaidFeature: false,
	},
	{
		Name:          "Event Subscriptions",
		IsPaidFeature: false,
	},
	{
		Name:          "IP Restrictions",
		IsPaidFeature: true,
	},
	{
		Name:          "API Keys",
		IsPaidFeature: false,
	},
	{
		Name:          "SSH Credentials",
		IsPaidFeature: false,
	},
	{
		Name:          "Authtokens",
		IsPaidFeature: false,
	},
	{
		Name:          "Bot Users",
		IsPaidFeature: false,
	},
	{
		Name:          "SSH Certificate Authorities",
		IsPaidFeature: true,
	},
	{
		Name:          "SSH Host Certificates",
		IsPaidFeature: true,
	},
	{
		Name:          "SSH User Certificates",
		IsPaidFeature: true,
	},
}

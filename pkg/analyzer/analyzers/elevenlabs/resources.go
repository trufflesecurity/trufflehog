package elevenlabs

// User hold the information about user to whom the key belongs to
type User struct {
	ID                 string
	Name               string
	SubscriptionTier   string
	SubscriptionStatus string
}

// Resources hold information about the resources the key has access
type Resource struct {
	ID         string
	Name       string
	Type       string
	Metadata   map[string]string
	Permission string
}

package elevenlabs

// User hold the information about user to whom the key belongs to
type User struct {
	ID                 string
	Name               string
	SubscriptionTier   string
	SubscriptionStatus string
}

// Resources hold information about all the resources the key has access to
type Resources struct {
	HistoryItemsID              []string
	Voices                      []Voice
	Projects                    []Project
	ProununciationDictionaiesID []string
	Models                      []Models
	Dubbings                    []Dubbing
}

type Voice struct {
	ID            string
	PublicOwnerID string // only for shared voices
	Name          string
}

type Project struct {
	ID   string
	Name string
}

type Models struct {
	ID   string
	Name string
}

type Dubbing struct {
	ID   string
	Name string
}

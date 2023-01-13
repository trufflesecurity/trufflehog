package npm

// package data structures

type pkg struct {
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Versions     map[string]version `json:"versions"`
	Maintainers  []maintainer       `json:"maintainers"`
	Repository   repository         `json:"repository"`
	Keywords     []string           `json:"keywords"`
	Contributors []contributors     `json:"contributors"`
}
type repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
type maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}
type dist struct {
	Tarball string `json:"tarball"`
}
type version struct {
	Version string `json:"version"`
	Dist    dist   `json:"dist"`
}
type contributors struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}
type npmUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// maintainer search

type maintainerRes struct {
	Objects []objects `json:"objects"`
	Total   int       `json:"total"`
}
type maintainerPkg struct {
	Name string `json:"name"`
}
type objects struct {
	Package maintainerPkg `json:"package,omitempty"`
}

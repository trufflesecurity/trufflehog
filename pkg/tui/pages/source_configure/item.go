package source_configure

type Item struct {
	title       string
	description string
}

func (i Item) ID() string { return i.title }

func (i Item) Title() string {
	return i.title
}
func (i Item) Description() string {
	return i.description
}

func (i Item) SetDescription(d string) Item {
	i.description = d
	return i
}

// We shouldn't be filtering for these list items.
func (i Item) FilterValue() string { return "" }

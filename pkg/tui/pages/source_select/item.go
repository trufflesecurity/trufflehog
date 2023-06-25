package source_select

type SourceItem struct {
	title       string
	description string
	enterprise  bool
}

func OssItem(title, description string) SourceItem {
	return SourceItem{title, description, false}
}

func EnterpriseItem(title, description string) SourceItem {
	return SourceItem{title, description, true}
}

func (i SourceItem) ID() string { return i.title }

func (i SourceItem) Title() string {
	if i.enterprise {
		return "💸 " + i.title
	}
	return i.title
}
func (i SourceItem) Description() string {
	if i.enterprise {
		return i.description + " (Enterprise only)"
	}
	return i.description
}

func (i SourceItem) FilterValue() string { return i.title + i.description }

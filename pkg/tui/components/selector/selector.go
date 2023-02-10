package selector

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/soft-serve/ui/common"
)

// Selector is a list of items that can be selected.
type Selector struct {
	list.Model
	common      common.Common
	active      int
	filterState list.FilterState
}

// IdentifiableItem is an item that can be identified by a string. Implements
// list.DefaultItem.
type IdentifiableItem interface {
	list.DefaultItem
	ID() string
}

// ItemDelegate is a wrapper around list.ItemDelegate.
type ItemDelegate interface {
	list.ItemDelegate
}

// SelectMsg is a message that is sent when an item is selected.
type SelectMsg struct{ IdentifiableItem }

// ActiveMsg is a message that is sent when an item is active but not selected.
type ActiveMsg struct{ IdentifiableItem }

// New creates a new selector.
func New(common common.Common, items []IdentifiableItem, delegate ItemDelegate) *Selector {
	itms := make([]list.Item, len(items))
	for i, item := range items {
		itms[i] = item
	}
	l := list.New(itms, delegate, common.Width, common.Height)
	s := &Selector{
		Model:  l,
		common: common,
	}
	s.SetSize(common.Width, common.Height)
	return s
}

// PerPage returns the number of items per page.
func (s *Selector) PerPage() int {
	return s.Model.Paginator.PerPage
}

// SetPage sets the current page.
func (s *Selector) SetPage(page int) {
	s.Model.Paginator.Page = page
}

// Page returns the current page.
func (s *Selector) Page() int {
	return s.Model.Paginator.Page
}

// TotalPages returns the total number of pages.
func (s *Selector) TotalPages() int {
	return s.Model.Paginator.TotalPages
}

// Select selects the item at the given index.
func (s *Selector) Select(index int) {
	s.Model.Select(index)
}

// SetShowTitle sets the show title flag.
func (s *Selector) SetShowTitle(show bool) {
	s.Model.SetShowTitle(show)
}

// SetShowHelp sets the show help flag.
func (s *Selector) SetShowHelp(show bool) {
	s.Model.SetShowHelp(show)
}

// SetShowStatusBar sets the show status bar flag.
func (s *Selector) SetShowStatusBar(show bool) {
	s.Model.SetShowStatusBar(show)
}

// DisableQuitKeybindings disables the quit keybindings.
func (s *Selector) DisableQuitKeybindings() {
	s.Model.DisableQuitKeybindings()
}

// SetShowFilter sets the show filter flag.
func (s *Selector) SetShowFilter(show bool) {
	s.Model.SetShowFilter(show)
}

// SetShowPagination sets the show pagination flag.
func (s *Selector) SetShowPagination(show bool) {
	s.Model.SetShowPagination(show)
}

// SetFilteringEnabled sets the filtering enabled flag.
func (s *Selector) SetFilteringEnabled(enabled bool) {
	s.Model.SetFilteringEnabled(enabled)
}

// SetSize implements common.Component.
func (s *Selector) SetSize(width, height int) {
	s.common.SetSize(width, height)
	s.Model.SetSize(width, height)
}

// SetItems sets the items in the selector.
func (s *Selector) SetItems(items []IdentifiableItem) tea.Cmd {
	its := make([]list.Item, len(items))
	for i, item := range items {
		its[i] = item
	}
	return s.Model.SetItems(its)
}

// Index returns the index of the selected item.
func (s *Selector) Index() int {
	return s.Model.Index()
}

// Init implements tea.Model.
func (s *Selector) Init() tea.Cmd {
	return s.activeCmd
}

// Update implements tea.Model.
func (s *Selector) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0)
	switch msg := msg.(type) {
	case tea.MouseMsg:
		switch msg.Type {
		case tea.MouseWheelUp:
			s.Model.CursorUp()
		case tea.MouseWheelDown:
			s.Model.CursorDown()
		case tea.MouseLeft:
			curIdx := s.Model.Index()
			for i, item := range s.Model.Items() {
				item, _ := item.(IdentifiableItem)
				// Check each item to see if it's in bounds.
				if item != nil && s.common.Zone.Get(item.ID()).InBounds(msg) {
					if i == curIdx {
						cmds = append(cmds, s.selectCmd)
					} else {
						s.Model.Select(i)
					}
					break
				}
			}
		}
	case tea.KeyMsg:
		filterState := s.Model.FilterState()
		switch {
		case key.Matches(msg, s.common.KeyMap.Help):
			if filterState == list.Filtering {
				return s, tea.Batch(cmds...)
			}
		case key.Matches(msg, s.common.KeyMap.Select):
			if filterState != list.Filtering {
				cmds = append(cmds, s.selectCmd)
			}
		}
	case list.FilterMatchesMsg:
		cmds = append(cmds, s.activeFilterCmd)
	}
	m, cmd := s.Model.Update(msg)
	s.Model = m
	if cmd != nil {
		cmds = append(cmds, cmd)
	}
	// Track filter state and update active item when filter state changes.
	filterState := s.Model.FilterState()
	if s.filterState != filterState {
		cmds = append(cmds, s.activeFilterCmd)
	}
	s.filterState = filterState
	// Send ActiveMsg when index change.
	if s.active != s.Model.Index() {
		cmds = append(cmds, s.activeCmd)
	}
	s.active = s.Model.Index()
	return s, tea.Batch(cmds...)
}

// View implements tea.Model.
func (s *Selector) View() string {
	return s.Model.View()
}

// SelectItem is a command that selects the currently active item.
func (s *Selector) SelectItem() tea.Msg {
	return s.selectCmd()
}

func (s *Selector) selectCmd() tea.Msg {
	item := s.Model.SelectedItem()
	i, ok := item.(IdentifiableItem)
	if !ok {
		return SelectMsg{}
	}
	return SelectMsg{i}
}

func (s *Selector) activeCmd() tea.Msg {
	item := s.Model.SelectedItem()
	i, ok := item.(IdentifiableItem)
	if !ok {
		return ActiveMsg{}
	}
	return ActiveMsg{i}
}

func (s *Selector) activeFilterCmd() tea.Msg {
	// Here we use VisibleItems because when list.FilterMatchesMsg is sent,
	// VisibleItems is the only way to get the list of filtered items. The list
	// bubble should export something like list.FilterMatchesMsg.Items().
	items := s.Model.VisibleItems()
	if len(items) == 0 {
		return nil
	}
	item := items[0]
	i, ok := item.(IdentifiableItem)
	if !ok {
		return nil
	}
	return ActiveMsg{i}
}

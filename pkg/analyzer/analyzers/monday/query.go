package monday

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

//go:embed query.graphql
var requestQuery string

type Request struct {
	Query string `json:"query"`
}

// Response is the Monday Graphql API response in case of success
type Response struct {
	Data Data `json:"data"`
}

type Data struct {
	Me         Me           `json:"me"`
	Account    Account      `json:"account"`
	Users      []User       `json:"users"`
	Boards     []Board      `json:"boards"`
	Docs       []Docs       `json:"docs"`
	Folders    []EntityRef  `json:"folders"`
	Tags       []EntityRef  `json:"tags"`
	Teams      []EntityRef  `json:"teams"`
	Workspaces []Workspaces `json:"workspaces"`
}

type EntityRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Me struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Email      string      `json:"email"`
	Title      *string     `json:"title"`
	IsAdmin    bool        `json:"is_admin"`
	IsGuest    bool        `json:"is_guest"`
	IsViewOnly bool        `json:"is_view_only"`
	IsPending  bool        `json:"is_pending"`
	IsVerified bool        `json:"is_verified"`
	Teams      []EntityRef `json:"teams"`
}

type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
	Tier string `json:"tier"`
}

type User struct {
	Email   string  `json:"email"`
	Account Account `json:"account"`
}

type Board struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	State       string      `json:"state"`
	Permissions string      `json:"permissions"`
	Groups      []Group     `json:"groups"`
	Columns     []Column    `json:"column"`
	Owners      []EntityRef `json:"owner"`
}

type Group struct {
	Title string `json:"title"`
	ID    string `json:"id"`
}

type Column struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Type  string `json:"type"`
}

type Docs struct {
	ID        string    `json:"id"`
	ObjectID  string    `json:"object_id"`
	Name      string    `json:"name"`
	CreatedBy EntityRef `json:"created_by"`
}

type Workspaces struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// captureMondayData send a request to Monday graphql API to get all data and capture it in secret info
func captureMondayData(client *http.Client, key string, secretInfo *SecretInfo) error {
	jsonData, err := json.Marshal(Request{Query: requestQuery})
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.monday.com/v2", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", key)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var apiResponse Response

		if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
			return err
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("expired/invalid access token")
	default:
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func responseToSecretInfo(apiResponse Response, secretInfo *SecretInfo) {
	secretInfo.User = apiResponse.Data.Me
	secretInfo.Account = apiResponse.Data.Account

	for _, board := range apiResponse.Data.Boards {
		boardResource := MondayResource{
			ID:   board.ID,
			Name: board.Name,
			Type: "Board",
			MetaData: map[string]string{
				"state":       board.State,
				"permissions": board.Permissions,
			},
		}

		secretInfo.appendResource(boardResource)

		for _, group := range board.Groups {
			secretInfo.appendResource(MondayResource{
				ID:     group.ID,
				Name:   group.Title,
				Type:   "Board Group",
				Parent: &boardResource,
			})
		}

		for _, column := range board.Columns {
			secretInfo.appendResource(MondayResource{
				ID:   column.ID,
				Name: column.Title,
				Type: "Board Column",
				MetaData: map[string]string{
					"Column Type": column.Type,
				},
				Parent: &boardResource,
			})
		}
	}
}

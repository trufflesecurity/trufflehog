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

const (
	// resource types
	TypeBoard       = "Board"
	TypeBoardGroup  = "Board Group"
	TypeBoardColumn = "Board Column"
	TypeDoc         = "Document"
	TypeFolder      = "Folder"
	TypeTag         = "Tag"
	TypeTeam        = "Team"
	TypeWorkspace   = "Workspace"
)

type Request struct {
	Query string `json:"query"`
}

// Response is the Monday Graphql API response in case of success
type Response struct {
	Data Data `json:"data"`
}

type Data struct {
	Me         Me          `json:"me"`
	Account    Account     `json:"account"`
	Users      []User      `json:"users"`
	Boards     []Board     `json:"boards"`
	Docs       []Doc       `json:"docs"`
	Folders    []EntityRef `json:"folders"`
	Tags       []EntityRef `json:"tags"`
	Teams      []EntityRef `json:"teams"`
	Workspaces []Workspace `json:"workspaces"`
}

type EntityRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Me struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Email      string      `json:"email"`
	Title      string      `json:"title"`
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

type Doc struct {
	ID        string    `json:"id"`
	ObjectID  string    `json:"object_id"`
	Name      string    `json:"name"`
	CreatedBy EntityRef `json:"created_by"`
}

type Workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
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

		// capture details in secret info
		responseToSecretInfo(apiResponse, secretInfo)

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("expired/invalid access token")
	default:
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// responseToSecretInfo translate api response to secret info
func responseToSecretInfo(apiResponse Response, secretInfo *SecretInfo) {
	secretInfo.User = apiResponse.Data.Me
	secretInfo.Account = apiResponse.Data.Account

	processBoards(apiResponse.Data.Boards, secretInfo)
	processDocs(apiResponse.Data.Docs, secretInfo)
	processSimpleEntities(apiResponse.Data.Folders, TypeFolder, secretInfo)
	processSimpleEntities(apiResponse.Data.Tags, TypeTag, secretInfo)
	processSimpleEntities(apiResponse.Data.Teams, TypeTeam, secretInfo)
	processWorkspaces(apiResponse.Data.Workspaces, secretInfo)
}

func processBoards(boards []Board, secretInfo *SecretInfo) {
	for _, board := range boards {
		boardResource := MondayResource{
			ID:   board.ID,
			Name: board.Name,
			Type: TypeBoard,
			MetaData: map[string]string{
				"state":       board.State,
				"permissions": board.Permissions,
			},
		}

		secretInfo.appendResource(boardResource)

		// sub resources of board
		for _, group := range board.Groups {
			secretInfo.appendResource(MondayResource{
				ID:     group.ID,
				Name:   group.Title,
				Type:   TypeBoardGroup,
				Parent: &boardResource,
			})
		}

		for _, column := range board.Columns {
			secretInfo.appendResource(MondayResource{
				ID:   column.ID,
				Name: column.Title,
				Type: TypeBoardColumn,
				MetaData: map[string]string{
					"Column Type": column.Type,
				},
				Parent: &boardResource,
			})
		}
	}
}

func processDocs(docs []Doc, secretInfo *SecretInfo) {
	for _, doc := range docs {
		secretInfo.appendResource(MondayResource{
			ID:   doc.ID,
			Name: doc.Name,
			Type: TypeDoc,
			MetaData: map[string]string{
				"created_by": doc.CreatedBy.Name,
			},
		})
	}
}

func processSimpleEntities(entities []EntityRef, entityType string, secretInfo *SecretInfo) {
	for _, entity := range entities {
		secretInfo.appendResource(MondayResource{
			ID:   entity.ID,
			Name: entity.Name,
			Type: entityType,
		})
	}
}

func processWorkspaces(workspaces []Workspace, secretInfo *SecretInfo) {
	for _, workspace := range workspaces {
		secretInfo.appendResource(MondayResource{
			ID:   workspace.ID,
			Name: workspace.Name,
			Type: TypeWorkspace,
			MetaData: map[string]string{
				"workspace_kind": workspace.Kind,
			},
		})
	}
}

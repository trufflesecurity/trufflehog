package trello

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const baseURL = "https://api.trello.com/1/"

type Source struct {
	name     string
	apiKey   string
	token    string
	boardIDs []string
	sourceId int64
	jobId    int64
	verify   bool
	jobPool  *errgroup.Group
	sources.Progress
	client *http.Client
	sources.CommonSourceUnitUnmarshaller
}

// Type returns the type of the source.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_TRELLO
}

// Init returns an initialized Source.
func (s *Source) Init(_ context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)
	s.client = common.RetryableHttpClientTimeout(3)

	var conn sourcespb.Trello
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.apiKey = conn.GetAuth().GetApiKey()
	s.token = conn.GetAuth().GetToken()
	s.boardIDs = conn.GetBoards()

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	scanErrs := sources.NewScanErrors()

	for _, boardID := range s.boardIDs {
		board, err := s.getBoard(ctx, boardID)
		if err != nil {
			scanErrs.Add(err)
			return nil
		}

		if err = s.chunkBoard(ctx, board, chunksChan); err != nil {
			scanErrs.Add(err)
			return nil
		}
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().V(2).Info("encountered errors while scanning", "count", scanErrs.Count(), "errors", scanErrs)
	}

	return nil
}

type board struct {
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	ID    string `json:"id"`
	URL   string `json:"url"`
}

type card struct {
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	ID    string `json:"id"`
	URL   string `json:"url"`
}

type action struct {
	Type string `json:"type"`
	Data struct {
		Text string `json:"text"`
	} `json:"data"`
}

// Add these two methods to Source
func (s *Source) getCards(_ context.Context, boardID string) ([]card, error) {
	reqURL := fmt.Sprintf("%sboards/%s/cards?key=%s&token=%s", baseURL, boardID, s.apiKey, s.token)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var cards []card
	if err := json.NewDecoder(res.Body).Decode(&cards); err != nil {
		return nil, err
	}

	return cards, nil
}

func (s *Source) getComments(_ context.Context, cardID string) ([]action, error) {
	reqURL := fmt.Sprintf("%scards/%s/actions?key=%s&token=%s", baseURL, cardID, s.apiKey, s.token)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var actions []action
	if err := json.NewDecoder(res.Body).Decode(&actions); err != nil {
		return nil, err
	}

	return actions, nil
}

func (s *Source) getBoard(_ context.Context, boardID string) (*board, error) {
	reqURL := fmt.Sprintf("%sboards/%s?key=%s&token=%s", baseURL, boardID, s.apiKey, s.token)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var b board
	if err := json.NewDecoder(res.Body).Decode(&b); err != nil {
		return nil, err
	}

	return &b, nil
}

func (s *Source) chunkBoard(ctx context.Context, board *board, chunksChan chan *sources.Chunk) error {
	err := s.chunkItem(ctx, chunksChan, board.ID, board.Desc, board.URL, source_metadatapb.ItemType_ITEM_TYPE_BOARD, board.Name)
	if err != nil {
		return err
	}

	cards, err := s.getCards(ctx, board.ID)
	if err != nil {
		return err
	}

	for _, card := range cards {
		err := s.chunkItem(ctx, chunksChan, card.ID, card.Desc, card.URL, source_metadatapb.ItemType_ITEM_TYPE_CARD, card.Name)
		if err != nil {
			return err
		}

		comments, err := s.getComments(ctx, card.ID)
		if err != nil {
			return err
		}

		for _, comment := range comments {
			if comment.Type != "commentCard" {
				continue
			}

			err := s.chunkItem(ctx, chunksChan, card.ID, comment.Data.Text, card.URL, source_metadatapb.ItemType_ITEM_TYPE_COMMENT, "")
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Source) chunkItem(ctx context.Context, chunksChan chan *sources.Chunk, id, text, url string, itemType source_metadatapb.ItemType, name string) error {
	data := []byte(text)

	chunk := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.sourceId,
		JobID:      s.jobId,
		Data:       data,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Trello{
				Trello: &source_metadatapb.Trello{
					Id:   id,
					Url:  url,
					Type: itemType,
					Name: name
				},
			},
		},
		Verify: s.verify,
	}

	atomic.AddInt64(&s.scannedBytes, int64(len(data)))

	if err := common.CancellableWrite(ctx, chunksChan, chunk); err != nil {
		return err
	}

	return nil
}

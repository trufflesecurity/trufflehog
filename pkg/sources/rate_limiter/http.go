package rate_limiter

import (
	"io"
	"net/http"
	"net/url"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type HTTPClient interface {
	CloseIdleConnections()
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (resp *http.Response, err error)
	Head(url string) (resp *http.Response, err error)
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
	PostForm(url string, data url.Values) (resp *http.Response, err error)
}

func httpDo[T HTTPClient](
	cli T,
	api *APIRateLimiter,
	req *http.Request,
) (*http.Response, error) {
	var ctx context.Context = req.Context().(context.Context)
	if ctx == nil {
		ctx = context.TODO()
	}

	do := func() (*http.Response, error) { return cli.Do(req) }

	return api.DoWithRateLimiting(ctx, req, do)
}

func httpGet[T HTTPClient](
	cli T,
	api *APIRateLimiter,
	url string,
) (*http.Response, error) {
	var ctx context.Context = req.Context().(context.Context)
	if ctx == nil {
		ctx = context.TODO()
	}

	get := func() (*http.Response, error) { return cli.Get(url) }

	return api.DoWithRateLimiting(ctx, req, get)
}

func httpHead[T HTTPClient](
	cli T,
	api *APIRateLimiter,
	url string,
) (*http.Response, error) {
	var ctx context.Context = req.Context().(context.Context)
	if ctx == nil {
		ctx = context.TODO()
	}

	head := func() (*http.Response, error) { return cli.Head(url) }

	return api.DoWithRateLimiting(ctx, req, head)
}

func httpPost[T HTTPClient](
	cli T,
	api *APIRateLimiter,
	url, contentType string,
	body io.Reader,
) (*http.Response, error) {
	var ctx context.Context = req.Context().(context.Context)
	if ctx == nil {
		ctx = context.TODO()
	}

	post := func() (*http.Response, error) {
		return cli.Post(url, contentType, body)
	}

	return api.DoWithRateLimiting(ctx, req, post)
}

func httpPostForm[T HTTPClient](
	cli T,
	api *APIRateLimiter,
	url string,
	data url.Values,
) (*http.Response, error) {
	var ctx context.Context = req.Context().(context.Context)
	if ctx == nil {
		ctx = context.TODO()
	}

	postForm := func() (*http.Response, error) { return cli.PostForm(url, data) }

	return api.DoWithRateLimiting(ctx, req, postForm)
}

type APIClient struct {
	httpClient  *http.Client
	rateLimiter *APIRateLimiter
}

func NewAPIClient(
	hostname string,
	limits map[string]APIRateLimit,
	httpClient *http.Client,
) (*APIClient, error) {
	rateLimiter, err := NewAPIRateLimiter(hostname, limits)
	if err != nil {
		return nil, err
	}

	return &APIClient{httpClient: httpClient, rateLimiter: rateLimiter}, nil
}

func (api *APIClient) CloseIdleConnections() {
	api.httpClient.CloseIdleConnections()
}

func (api *APIClient) Do(req *http.Request) (*http.Response, error) {
	return httpDo(api.httpClient, api.rateLimiter, req)
}

func (api *APIClient) Get(url string) (resp *http.Response, err error) {
	return httpGet(api.httpClient, api.rateLimiter, url)
}

func (api *APIClient) Head(url string) (resp *http.Response, err error) {
	return httpHead(api.httpClient, api.rateLimiter, url)
}

func (api *APIClient) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
}

func (api *APIClient) PostForm(url string, data url.Values) (resp *http.Response, err error) {
}

package postman

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func (s *Source) parseAPIKey(a Auth) string {
	var data, apiKeyValue, apiKeyName string
	for _, kv := range a.Apikey {
		switch kv.Key {
		case "key":
			apiKeyValue = fmt.Sprintf("%v", kv.Value)
		case "value":
			apiKeyName = fmt.Sprintf("%v", kv.Value)
		}
	}
	data += fmt.Sprintf("%s=%s\n", apiKeyName, apiKeyValue)
	for _, keyword := range filterKeywords(s.keywords, s.detectorKeywords) {
		data += fmt.Sprintf("%s:%s\n ", keyword, apiKeyValue)
	}

	return data
}

func (s *Source) parseAWSAuth(a Auth) string {
	data := ""
	for _, kv := range a.AWSv4 {
		switch kv.Key {
		case "accessKey":
			data += fmt.Sprintf("accessKey:%s ", kv.Value)
		case "secretKey":
			data += fmt.Sprintf("secretKey:%s ", kv.Value)
		case "region":
			data += fmt.Sprintf("region:%s ", kv.Value)
		case "service":
			data += fmt.Sprintf("service:%s ", kv.Value)
		}
	}
	return data
}

func (s *Source) parseBearer(a Auth) string {
	var data, bearerKey, bearerValue string
	for _, kv := range a.Bearer {
		bearerValue = fmt.Sprintf("%v", kv.Value)
		bearerKey = fmt.Sprintf("%v", kv.Key)
	}
	data += fmt.Sprintf("%s:%s\n", bearerKey, bearerValue)
	for _, keyword := range filterKeywords(s.keywords, s.detectorKeywords) {
		data += fmt.Sprintf("%s:%s ", keyword, bearerValue)
	}
	return data
}

func (s *Source) parseBasicAuth(ctx context.Context, a Auth, u URL) string {
	if len(a.Basic) == 0 {
		return ""
	}

	// inject filtered keywords into top of data chunk
	keywords := filterKeywords(s.keywords, s.detectorKeywords)
	data := strings.Join(keywords, " ") + "\n"

	username := ""
	password := ""

	for _, kv := range a.Basic {
		switch kv.Key {
		case "username":
			username = fmt.Sprintf("%v", kv.Value)
		case "password":
			password = fmt.Sprintf("%v", kv.Value)
		}
	}
	if u.Raw != "" {
		parsedURL, err := url.Parse(u.Raw)
		if err != nil {
			ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
			return data
		}

		parsedURL.User = url.User(username + ":" + password)
		decodedURL, err := url.PathUnescape(parsedURL.String())
		if err != nil {
			ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
			return data
		}
		data += (s.substitute(decodedURL) + " ")
	}

	return data
}

func (s *Source) parseOAuth2(a Auth) string {
	if len(a.OAuth2) == 0 {
		return ""
	}
	var data string
	for _, oauth := range a.OAuth2 {
		switch oauth.Key {
		case "accessToken", "refreshToken", "clientId", "clientSecret", "accessTokenUrl", "authUrl":
			data += fmt.Sprintf("%s:%v ", oauth.Key, oauth.Value)
			for _, keyword := range s.keywords {
				data += fmt.Sprintf("%s:%v ", keyword, oauth.Value)
			}
		}
	}
	// for _, subMap := range *varSubMap {
	// 	data += s.substitute(data, subMap)
	// }
	return data
}

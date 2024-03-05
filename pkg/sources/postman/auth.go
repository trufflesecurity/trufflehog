package postman

import (
	"fmt"
	"net/url"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func (s *Source) parseAPIKey(a Auth) string {
	if len(a.Apikey) == 0 {
		return ""
	}
	var data string
	var apiKeyValue string
	var apiKeyName string
	for _, kv := range a.Apikey {
		switch kv.Key {
		case "key":
			apiKeyValue = fmt.Sprintf("%v", kv.Value)
		case "value":
			apiKeyName = fmt.Sprintf("%v", kv.Value)
		}
	}
	data += fmt.Sprintf("%s=%s\n", apiKeyName, apiKeyValue)
	for _, keyword := range s.keywords {
		data += fmt.Sprintf("%s:%s ", keyword, apiKeyValue)
	}

	// ZRNOTE: kinda confused by this one
	// for _, subMap := range *varSubMap {
	// 	// Substitute for both key and value, for both regular and keyword subbed in
	// 	data += s.substitute(data, subMap)
	// }
	return data
}

func (s *Source) parseAWSAuth(a Auth) string {
	if len(a.AWSv4) == 0 {
		return ""
	}
	var data string
	var awsAccessKey string
	var awsSecretKey string
	var awsRegion string
	var awsService string
	for _, kv := range a.AWSv4 {
		switch kv.Key {
		case "accessKey":
			awsAccessKey = fmt.Sprintf("%v", kv.Value)
		case "secretKey":
			awsSecretKey = fmt.Sprintf("%v", kv.Value)
		case "region":
			awsRegion = fmt.Sprintf("%v", kv.Value)
		case "service":
			awsService = fmt.Sprintf("%v", kv.Value)
		}
	}
	data += fmt.Sprintf("accessKey:%s secretKey:%s region:%s service:%s\n", awsAccessKey, awsSecretKey, awsRegion, awsService)
	// for _, subMap := range *varSubMap {
	// 	data += s.substitute(data, subMap)
	// }
	return data
}

func (s *Source) parseBearer(a Auth) string {
	if len(a.Bearer) == 0 {
		return ""
	}
	var data, bearerKey, bearerValue string
	for _, kv := range a.Bearer {
		bearerValue = fmt.Sprintf("%v", kv.Value)
		bearerKey = fmt.Sprintf("%v", kv.Key)
	}
	data += fmt.Sprintf("%s:%s\n", bearerKey, bearerValue)
	for _, keyword := range s.keywords {
		data += fmt.Sprintf("%s:%s ", keyword, bearerValue)
	}
	// for _, subMap := range *varSubMap {
	// 	// Substitute for both key and value, for both regular and keyword subbed in
	// 	data += s.substitute(data, subMap)
	// }
	return data
}

func (s *Source) parseBasicAuth(ctx context.Context, a Auth, u URL) string {
	if len(a.Basic) == 0 {
		return ""
	}
	var data, basicUsername, basicPassword string
	for _, kv := range a.Basic {
		switch kv.Key {
		case "username":
			basicUsername = fmt.Sprintf("%v", kv.Value)
		case "password":
			basicPassword = fmt.Sprintf("%v", kv.Value)
		}
	}
	// ZRNOTE: if either username or pw are empty, we should return an empty string?
	data += fmt.Sprintf("username:%s password:%s ", basicUsername, basicPassword)
	for _, keyword := range s.keywords {
		data += fmt.Sprintf("%s:%s ", keyword, basicPassword)
	}

	if u.Raw != "" {
		// Question: Do we still need keywords located near https://username:password@domain?
		parsedURL, err := url.Parse(u.Raw)
		if err != nil {
			ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
			return data
		}

		parsedURL.User = url.User(basicUsername + ":" + basicPassword)
		decodedURL, err := url.PathUnescape(parsedURL.String())
		if err != nil {
			ctx.Logger().V(2).Info("error parsing URL in basic auth check", "url", u.Raw)
			return data
		}
		data += (decodedURL + " ")
	}

	// for _, subMap := range *varSubMap {
	// 	data += s.substitute(data, subMap)
	// }

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

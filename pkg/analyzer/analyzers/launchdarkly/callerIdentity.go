/*
callerIdentity.go file is all related to calling APIs to get caller and token information and formatting them to secretInfo CallerIdentity.

It calls 3 APIs:
  - /v2/caller-identity
  - /v2/tokens/<id> (with token id from previous api response)
  - /v2/roles/<role_id> (if custom role id is present in tokens) (more than one role can be assigned to token as well)

it formats all these responses into one CallerIdentity struct for secretInfo.
*/
package launchdarkly

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// callerIdentityResponse is /v2/caller-identity API response
type callerIdentityResponse struct {
	AccountID    string `json:"accountId"`
	TokenName    string `json:"tokenName"`
	TokenID      string `json:"tokenId"`
	MemberID     string `json:"memberId"`
	ServiceToken bool   `json:"serviceToken"`
}

// tokenResponse is the /v2/tokens/<id> API response
type tokenResponse struct {
	OwnerID           string              `json:"ownerId"`
	Member            tokenMemberResponse `json:"_member"`
	Name              string              `json:"name"`
	CustomRoleIDs     []string            `json:"customRoleIds"`
	InlineRole        tokenPolicyResponse `json:"inlineRole"`
	Role              string              `json:"role"`
	ServiceToken      bool                `json:"serviceToken"`
	DefaultAPIVersion int                 `json:"defaultApiVersion"`
}

// _member object in token response
type tokenMemberResponse struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Role      string `json:"role"`
	Email     string `json:"email"`
}

// inlineRole object in token response
type tokenPolicyResponse struct {
	Effect       string   `json:"effect"`
	Resources    []string `json:"resources"`
	NotResources []string `json:"notResources"`
	Actions      []string `json:"actions"`
	NotActions   []string `json:"notActions"`
}

// customRoleResponse is the /v2/roles/<role_id> API response
type customRoleResponse struct {
	ID             string                `json:"_id"`
	Key            string                `json:"key"`
	Name           string                `json:"name"`
	Policy         []tokenPolicyResponse `json:"policy"`
	BasePermission string                `json:"basePermissions"`
	AssignedTo     struct {
		MembersCount int `json:"membersCount"`
		TeamsCount   int `json:"teamsCount"`
	} `json:"assignedTo"`
}

/*
fetchCallerDetails call following three APIs:
  - /v2/caller-identity
  - /v2/tokens/<token_id> (token_id from previous API response)
  - /v2/roles/<role_id> (roles_id from previous API response if exist)

It format all responses into one secret info CallerIdentity
*/
func fetchCallerDetails(client *http.Client, token string) (*CallerIdentity, error) {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints["callerIdentity"], token)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK:
		var caller callerIdentityResponse

		if err := json.Unmarshal(response, &caller); err != nil {
			return nil, err
		}

		tokenDetails, err := getToken(client, caller.TokenID, token)
		if err != nil {
			return nil, err
		}

		customRoles, err := getCustomRole(client, tokenDetails.CustomRoleIDs, token)
		if err != nil {
			return nil, err
		}

		return makeCallerIdentity(caller, *tokenDetails, customRoles), nil
	case http.StatusUnauthorized:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// getToken call /v2/tokens/<token_id> API and return response
func getToken(client *http.Client, tokenID, token string) (*tokenResponse, error) {
	response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints["getToken"], tokenID), token)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK:
		var token tokenResponse

		if err := json.Unmarshal(response, &token); err != nil {
			return nil, err
		}

		return &token, nil
	case http.StatusUnauthorized:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// getCustomRole call /v2/roles/<role_id> API  for all IDs passed and return list of responses
func getCustomRole(client *http.Client, customRoleIDs []string, token string) ([]customRoleResponse, error) {
	var customRoles []customRoleResponse

	for _, customRoleID := range customRoleIDs {
		response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints["getRole"], customRoleID), token)
		if err != nil {
			return nil, err
		}

		switch statusCode {
		case http.StatusOK:
			var customRole customRoleResponse

			if err := json.Unmarshal(response, &customRole); err != nil {
				return nil, err
			}

			customRoles = append(customRoles, customRole)
		case http.StatusUnauthorized:
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected status code: %d", statusCode)
		}
	}

	return customRoles, nil
}

// makeCallerIdentity take caller, tokenDetails, and customRoles and return secret info CallerIdentity
func makeCallerIdentity(caller callerIdentityResponse, tokenDetails tokenResponse, customRoles []customRoleResponse) *CallerIdentity {
	return &CallerIdentity{
		AccountID: caller.AccountID,
		MemberID:  caller.MemberID,
		Name:      tokenDetails.Member.FirstName + " " + tokenDetails.Member.LastName,
		Role:      tokenDetails.Member.Role,
		Email:     tokenDetails.Member.Email,
		Token: Token{
			ID:             caller.TokenID,
			Name:           tokenDetails.Name,
			Role:           tokenDetails.Role,
			APIVersion:     tokenDetails.DefaultAPIVersion,
			IsServiceToken: tokenDetails.ServiceToken,
			InlineRole:     toPolicy(tokenDetails.InlineRole),
			CustomRoles:    toCustomRoles(customRoles),
		},
	}
}

// toPolicy convert inlinePolicy from token response to secret info caller identity policy
func toPolicy(inlinePolices ...tokenPolicyResponse) []Policy {
	var policies = make([]Policy, len(inlinePolices))
	for _, inlinePolicy := range inlinePolices {
		policies = append(policies, Policy{
			Resources:    inlinePolicy.Resources,
			NotResources: inlinePolicy.NotResources,
			Actions:      inlinePolicy.Actions,
			NotActions:   inlinePolicy.NotActions,
			Effect:       inlinePolicy.Effect,
		})
	}

	return policies
}

// toCustomRoles convert customRole from token response to secret info caller identity custom role
func toCustomRoles(roles []customRoleResponse) []CustomRole {
	var customRoles = make([]CustomRole, len(roles))
	for _, role := range roles {
		customRoles = append(customRoles, CustomRole{
			ID:                role.ID,
			Key:               role.Key,
			Name:              role.Name,
			Polices:           toPolicy(role.Policy...),
			BasePermission:    role.BasePermission,
			AssignedToMembers: role.AssignedTo.MembersCount,
			AssignedToTeams:   role.AssignedTo.TeamsCount,
		})
	}

	return customRoles
}

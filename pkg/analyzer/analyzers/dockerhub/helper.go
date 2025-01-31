package dockerhub

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// permission hierarchy
var permissionHierarchy = []string{"repo:admin", "repo:write", "repo:read", "repo:public_read"}

// decodeTokenToSecretInfo decode the jwt token and add the information to secret info
func decodeTokenToSecretInfo(jwtToken string, secretInfo *SecretInfo) error {
	type userClaims struct {
		ID       string `json:"uuid"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	type hubJwtClaims struct {
		Scope     string     `json:"scope"`
		HubClaims userClaims `json:"https://hub.docker.com"`
		ExpiresIn int        `json:"exp"`
		jwt.RegisteredClaims
	}

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(jwtToken, &hubJwtClaims{})
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(*hubJwtClaims); ok {
		secretInfo.User = User{
			ID:       claims.HubClaims.ID,
			Username: claims.HubClaims.Username,
			Email:    claims.HubClaims.Email,
		}

		secretInfo.ExpiresIn = humandReadableTime(claims.ExpiresIn)

		secretInfo.Permissions = append(secretInfo.Permissions, claims.Scope)
		secretInfo.Valid = true

		return nil
	}

	return errors.New("failed to parse claims")
}

// repositoriesToSecretInfo translate repositories to secretInfo after sorting them
func repositoriesToSecretInfo(username string, repos *RepositoriesResponse, secretInfo *SecretInfo) {
	// sort the repositories first
	sortRepositories(repos)

	for _, repo := range repos.Result {
		secretInfo.Repositories = append(secretInfo.Repositories, Repository{
			// as repositories does not have a unique key, we make one by combining multiple fields
			ID:        fmt.Sprintf("%s/repo/%s/%s", username, repo.Type, repo.Name), // e.g: user123/repo/image/repo1
			Name:      repo.Name,
			Type:      repo.Type,
			IsPrivate: repo.IsPrivate,
			StarCount: repo.StarCount,
			PullCount: repo.PullCount,
		})
	}
}

/*
sortRepositories sort the repositories as following

private:
  - pullcount(descending)
  - starcount(descending)

public:
  - pullcount(descending)
  - starcount(descending)
*/
func sortRepositories(repos *RepositoriesResponse) {
	sort.SliceStable(repos.Result, func(i, j int) bool {
		a, b := repos.Result[i], repos.Result[j]

		// prioritize private repositories over public
		if a.IsPrivate != b.IsPrivate {
			return a.IsPrivate
		}

		// sort by Pull Count (descending)
		if a.PullCount != b.PullCount {
			return a.PullCount > b.PullCount
		}

		// sort by Star Count (descending)
		return a.StarCount > b.StarCount
	})
}

// assignHighestPermission selects the highest available permission
func assignHighestPermission(permissions []string) string {
	// create a map to quickly check assigned permissions
	available := make(map[string]bool)
	for _, perm := range permissions {
		available[perm] = true
	}

	// assign the highest available permission
	for _, perm := range permissionHierarchy {
		if available[perm] {
			return perm
		}
	}

	// return empty if no valid permission is found
	return ""
}

// humandReadableTime converts seconds to days, hours, minutes, or seconds based on the value
func humandReadableTime(seconds int) string {
	// Convert Unix timestamp to time.Time object
	t := time.Unix(int64(seconds), 0)

	// Format the time as "March 2" (Month Day format)
	return t.Format("January 2, 2006")
}

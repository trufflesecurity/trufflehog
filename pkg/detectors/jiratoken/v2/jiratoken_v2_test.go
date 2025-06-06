package jiratoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestJiraToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name       string
		input      string
		want       []string
		noKeywords bool
	}{
		{
			name: "valid pattern",
			input: `
					{
					"expand": "schema,names",
					"startAt": 0,
					"maxResults": 50,
					"total": 1,
					"issues": [
						{
							"expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
							"id": "fake454",
							"self": "https://example.atlassian.net/rest/api/2/issue/fake454",
							"key": "ESI-5555",
							"fields": {
								"statuscategorychangedate": "2016-06-01T01:25:35.807-0700",
								"issuetype": {
								"self": "https://example.atlassian.net/rest/api/2/issuetype/09090",
								"id": "09090",
								"description": "This is an example ticket. Here's the token to test JIRA APIs: ATATThktLkSzzcXi1xt19IlU6gAchV1TS83w11YOqAXqFUeA2=Yx3ssoNC",
								"name": "Example Pattern test",
								"subtask": false,
								"avatarId": 1298,
								"entityId": "93a51c1d-fake-4673-a71d-0889fake1238",
								"hierarchyLevel": 0,
								"emailAddress": "trufflesecurity@example.com",
							},
						}
					]}`,
			want: []string{"trufflesecurity@example.com" + ":" + "ATATThktLkSzzcXi1xt19IlU6gAchV1TS83w11YOqAXqFUeA2=Yx3ssoNC" + ":" + "example.atlassian.net"},
		},
		{
			name: "valid pattern - without domain",
			input: `
					{
					"expand": "schema,names",
					"startAt": 0,
					"maxResults": 50,
					"total": 1,
					"issues": [
						{
							"expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
							"id": "fake454",
							"key": "ESI-5555",
							"fields": {
								"statuscategorychangedate": "2016-06-01T01:25:35.807-0700",
								"issuetype": {
								"id": "09090",
								"description": "This is an example ticket. Here's the token to test JIRA APIs: ATATThktLkSzzcXi1xt19IlU6gAchV1TS83w11YOqAXqFUeA2=Yx3ssoNC",
								"name": "Example Pattern test 2",
								"subtask": false,
								"avatarId": 1298,
								"entityId": "93a51c1d-fake-4673-a71d-0889fake1238",
								"hierarchyLevel": 0,
								"emailAddress": "trufflesecurity@example.com",
							},
						}
					]}`,
			want: []string{"trufflesecurity@example.com" + ":" + "ATATThktLkSzzcXi1xt19IlU6gAchV1TS83w11YOqAXqFUeA2=Yx3ssoNC" + ":" + "api.atlassian.com"},
		},
		{
			name: "valid pattern - without token",
			input: `
					{
					"expand": "schema,names",
					"startAt": 0,
					"maxResults": 50,
					"total": 1,
					"issues": [
						{
							"expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
							"id": "fake454",
							"key": "ESI-5555",
							"fields": {
								"statuscategorychangedate": "2016-06-01T01:25:35.807-0700",
								"issuetype": {
								"id": "09090",
								"self": "https://example.atlassian.net/rest/api/2/issuetype/09090",
								"description": "This is an example ticket",
								"name": "Example Pattern test 2",
								"subtask": false,
								"avatarId": 1298,
								"entityId": "93a51c1d-fake-4673-a71d-0889fake1238",
								"hierarchyLevel": 0,
								"emailAddress": "trufflesecurity@example.com",
							},
						}
					]}`,
			want: []string{},
		},
		{
			name: "valid pattern - without email",
			input: `
					{
					"expand": "schema,names",
					"startAt": 0,
					"maxResults": 50,
					"total": 1,
					"issues": [
						{
							"expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
							"id": "fake454",
							"key": "ESI-5555",
							"fields": {
								"statuscategorychangedate": "2016-06-01T01:25:35.807-0700",
								"issuetype": {
								"id": "09090",
								"self": "https://example.atlassian.net/rest/api/2/issuetype/09090",
								"description": "This is an example ticket. Here's the token to test JIRA APIs: ATATThktLkSzzcXi1xt19IlU6gAchV1TS83w11YOqAXqFUeA2=Yx3ssoNC",
								"name": "Example Pattern test 2",
								"subtask": false,
								"avatarId": 1298,
								"entityId": "93a51c1d-fake-4673-a71d-0889fake1238",
								"hierarchyLevel": 0,
								"emailAddress": "",
							},
						}
					]}`,
			want: []string{},
		},
		{
			name: "valid pattern - without keywords",
			input: `
					{
					"expand": "schema,names",
					"startAt": 0,
					"maxResults": 50,
					"total": 1,
					"issues": [
						{
							"expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
							"id": "fake454",
							"key": "ESI-5555",
							"fields": {
								"statuscategorychangedate": "2016-06-01T01:25:35.807-0700",
								"issuetype": {
								"id": "09090",
								"description": "ATATThktLkSzzcXi1xt19IlU6gAchV1TS83w11YOqAXqFUeA2=Yx3ssoNC",
								"name": "Example Pattern test 2",
								"subtask": false,
								"avatarId": 1298,
								"entityId": "93a51c1d-fake-4673-a71d-0889fake1238",
								"hierarchyLevel": 0,
								"emailAddress": "trufflesecurity@example.com",
							},
						}
					]}`,
			want:       []string{},
			noKeywords: true,
		},
		{
			name: "invalid pattern",
			input: `
					{
					"expand": "schema,names",
					"startAt": 0,
					"maxResults": 50,
					"total": 1,
					"issues": [
						{
							"expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
							"id": "fake454",
							"key": "ESI-5555",
							"fields": {
								"statuscategorychangedate": "2016-06-01T01:25:35.807-0700",
								"issuetype": {
								"id": "09090",
								"description": "This is an example ticket. Here's the token to test JIRA APIs: ATATTA9nsCA?a7812Z7VoI%YJ0K4rFWLBfk91rhOsLAW=Yx3ssoNC",
								"name": "Example Pattern test 2",
								"subtask": false,
								"avatarId": 1298,
								"entityId": "93a51c1d-fake-4673-a71d-0889fake1238",
								"hierarchyLevel": 0,
								"emailAddress": "?y4r3fs1ewqec12v1e3tl.5Hcsrcehic89saXd.ro@",
							},
						}
					]}`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				// if intentionally no keywords are passed
				if test.noKeywords {
					return
				}

				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

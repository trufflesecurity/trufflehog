package denodeploy

import (
	"context"
	"testing"
)

func TestDenoDeploy_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		{
			name: `valid_deployctl`,
			data: `  "tasks": {
  	"d": "deployctl deploy --prod --import-map=import_map.json --project=o88 main.ts --token ddp_eg5DjUmbR5lHZ3LiN9MajMk2tA1GxL2NRdvc",
    "start": "deno run -A --unstable --watch=static/,routes/ dev.ts"
  },`,
			shouldMatch: true,
			match:       `ddp_eg5DjUmbR5lHZ3LiN9MajMk2tA1GxL2NRdvc`,
		},
		{
			name:        `valid_dotenv`,
			data:        `DENO_KV_ACCESS_TOKEN=ddp_hn029Cl2dIN4Jb0BF0L1V9opokoPVC30ddGk`,
			shouldMatch: true,
			match:       `ddp_hn029Cl2dIN4Jb0BF0L1V9opokoPVC30ddGk`,
		},
		{
			name: `valid_dotfile`,
			data: `# deno
export DENO_INSTALL="/home/khushal/.deno"
export PATH="$DENO_INSTALL/bin:$PATH"
export DENO_DEPLOY_TOKEN="ddp_QLbDfRlMKpXSf3oCz20Hp8wVVxThDwlwhFbV""`,
			shouldMatch: true,
			match:       `ddp_QLbDfRlMKpXSf3oCz20Hp8wVVxThDwlwhFbV`,
		},
		{
			name:        `valid_webtoken`,
			data:        `    //     headers: { Authorization: 'Bearer ddw_ebahKKeZqiZVXOad7KJRHskLeP79Lf0OJXlj' }`,
			shouldMatch: true,
			match:       `ddw_ebahKKeZqiZVXOad7KJRHskLeP79Lf0OJXlj`,
		},

		// False positives
		{
			name: `invalid_token1`,
			data: `                "summoner2Id": 4,
                "summonerId": "oljqJ1Ddp_LJm5s6ONPAJXIl97Bi6pcKMywYLG496a58rA",
                "summonerLevel": 146,`,
			shouldMatch: false,
		},
		{
			name:        `invalid_token2`,
			data:        `        "image_thumbnail_url": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQFq6zzTXpXtRDdP_JbNkS58loAyCvhhZ1WWONaUkJoWbHsgwIJBw",`,
			shouldMatch: false,
		},
		{
			name:        `invalid_token3`,
			data:        `matplotlib/backends/_macosx.cpython-37m-darwin.so,sha256=DDw_KRE5yTUEY5iDBwBW7KvDcTkDmrIu0N18i8I3FvA,90140`,
			shouldMatch: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("DenoDeploy.FromData() error = %v", err)
				return
			}

			if test.shouldMatch {
				if len(results) == 0 {
					t.Errorf("%s: did not receive a match for '%v' when one was expected", test.name, test.data)
					return
				}
				expected := test.data
				if test.match != "" {
					expected = test.match
				}
				result := results[0]
				resultData := string(result.Raw)
				if resultData != expected {
					t.Errorf("%s: did not receive expected match.\n\texpected: '%s'\n\t  actual: '%s'", test.name, expected, resultData)
					return
				}
			} else {
				if len(results) > 0 {
					t.Errorf("%s: received a match for '%v' when one wasn't wanted", test.name, test.data)
					return
				}
			}
		})
	}
}

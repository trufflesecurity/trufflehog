//go:build detectors
// +build detectors

package scrapingbee

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestScrapingBee_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		{
			name: `valid_query_param`,
			data: ` #CHANGE API KEY TO CURRENT API KEY ON SCRAPINGBEE BELOW:
  uri = URI("https://app.scrapingbee.com/api/v1/?api_key=VNC7VJ04BQLZWL821KJ4ZLG17ON45K4Y56P59QZMDNZBWRFAS0LIK47I3KFH6AMLUXPHIUIFBDOMIOUE&url=#{url}&stealth_proxy=True&country_code=sg&wait_browser=networkidle2&json_response=True&block_resources=False&block_ads=True&js_scenario=" + CGI.escape(js_scenario))`,
			shouldMatch: true,
			match:       `VNC7VJ04BQLZWL821KJ4ZLG17ON45K4Y56P59QZMDNZBWRFAS0LIK47I3KFH6AMLUXPHIUIFBDOMIOUE`,
		},
		{
			name: `valid_function_comment`,
			data: `func connectToScrapingBee() {
	// API KEY = M977YHXCMPJJ569DSB0B8KSKL9NRU2O2327MIDT55785T8LS9TJGDW4GFMCMOZNRVN3GPSXF0Y6DGC32`,
			shouldMatch: true,
			match:       `M977YHXCMPJJ569DSB0B8KSKL9NRU2O2327MIDT55785T8LS9TJGDW4GFMCMOZNRVN3GPSXF0Y6DGC32`,
		},
		{
			name: `valid_csharp`,
			data: `  class test{

      private static string BASE_URL = @"https://app.scrapingbee.com/api/v1/";
      private static string API_KEY = "2OZ3HPYEUP9LVCN9TSMBEP5OU0C65AXL7MDO76VPYQNVAJW8NU0QUQQPEV7C51XQDLZUUYKZ5TAW2L85";

      public static string Get(string url)`,
			shouldMatch: true,
			match:       `2OZ3HPYEUP9LVCN9TSMBEP5OU0C65AXL7MDO76VPYQNVAJW8NU0QUQQPEV7C51XQDLZUUYKZ5TAW2L85`,
		},
		{
			name: `valid_js1`,
			data: `  const options = {
    uri: "https://app.scrapingbee.com/api/v1?",
    qs: {
      api_key:
        "34TOQQ77QJALLR07ISPYL4B5EYHW3YLU5GM97GQOCA32BVW3S0S6RTVFCZGTHZ1Q5MHH1Z9GZ0B640LI",
      url: "https://www.metmuseum.org/art/collection/search/${node}",
		},
	};`,
			shouldMatch: true,
			match:       `34TOQQ77QJALLR07ISPYL4B5EYHW3YLU5GM97GQOCA32BVW3S0S6RTVFCZGTHZ1Q5MHH1Z9GZ0B640LI`,
		},
		{
			name: `valid_js2`,
			data: `  useEffect(() => {
    setLoading(true)
    base.get('https://app.scrapingbee.com/api/v1', {
      params: {
        'api_key': 'BYZCNNS0SOZCPC4EXD5SXSH0PWAXPWFMZ4SXVEQNEDMKSGBP57K31PJ44V46344XCYN7IARKQWLS0V3X',
        'url': 'https://www.flipkart.com/search?q=${searchItem}',
			'block_resources': 'false',
		}
	}).then((response) => {`,
			shouldMatch: true,
			match:       `BYZCNNS0SOZCPC4EXD5SXSH0PWAXPWFMZ4SXVEQNEDMKSGBP57K31PJ44V46344XCYN7IARKQWLS0V3X`,
		},
		{
			name: `valid_js3`,
			data: `const scrapingBeeApiKey =
  "P5IS953T7OYL5KJG8J3SVPAV5VUJ49L2OXB7HIQDVL8SSG7O9A3J6DQ6CTK65KEAM7L7MQJIEW20ZOCP"; // Replace 'YOUR_SCRAPING_BEE_API_KEY' with your actual API key`,
			shouldMatch: true,
			match:       `P5IS953T7OYL5KJG8J3SVPAV5VUJ49L2OXB7HIQDVL8SSG7O9A3J6DQ6CTK65KEAM7L7MQJIEW20ZOCP`,
		},
		{
			name: `valid_php`,
			data: `// Set base url & API key
$BASE_URL = "https://app.scrapingbee.com/api/v1/?";
$API_KEY = "R4EEK5MWM2GXNK1TZUU9Z0EBA29ZUW7PW12MHI4T1BHSR7GM1G37C5BL2NHLPWC0J6VOQWP5IZJ15QV8";
`,
			shouldMatch: true,
			match:       `R4EEK5MWM2GXNK1TZUU9Z0EBA29ZUW7PW12MHI4T1BHSR7GM1G37C5BL2NHLPWC0J6VOQWP5IZJ15QV8`,
		},
		{
			name:        `valid_python_sdk`,
			data:        `client = ScrapingBeeClient(api_key='MZ13G1AVV8C5MEYVOIMIGJEPUH0PBSJPYTCO6IUWRZS3BXNOLA4TUP27ZGQ97LS8NRBCO66WF3ZUKSFX')`,
			shouldMatch: true,
			match:       `MZ13G1AVV8C5MEYVOIMIGJEPUH0PBSJPYTCO6IUWRZS3BXNOLA4TUP27ZGQ97LS8NRBCO66WF3ZUKSFX`,
		},
		{
			name: `valid_python_sdk_newline`,
			data: `def main():
    client = ScrapingBeeClient(
        api_key='E1PJA1D78TBTM320Z8O9XS2MTWHTCL1NSJXGFKIZO6TJB4XIM94OSR6KQNU415QB97MYJEP6T3O0IWR3')`,
			shouldMatch: true,
			match:       `E1PJA1D78TBTM320Z8O9XS2MTWHTCL1NSJXGFKIZO6TJB4XIM94OSR6KQNU415QB97MYJEP6T3O0IWR3`,
		},
		{
			name: `valid_python_notebook`,
			data: `   "source": [
    "Every time you call any function there is an HTTPS request to Google's servers. To prevent your servers IP address being locked by Google we sould use a service that handles proxy rotation for us. In this case we are using **ScrapingBee API**.\n",
    "\n",
    "ScrapingBee API key:\n",
    "\n",
    "    QEUXIXLN8OULIISPZ1FXZUCWF7M42ZOUXRV7491R6RYQTFCSV8A4Y1B2YFPCD0HL2X62KPGTHFODSW6G\n",
    "\n",
    "NOTE: This API key is available till 08 March 2021 and expires after 200 requests  \n",
    "NOTE: **this Python package still works out of the box**."
   ]`,
			shouldMatch: true,
			match:       `QEUXIXLN8OULIISPZ1FXZUCWF7M42ZOUXRV7491R6RYQTFCSV8A4Y1B2YFPCD0HL2X62KPGTHFODSW6G`,
		},
		{
			name: `valid_python_nonapiurl`,
			data: `##########################################################################################################
# We use the best scraper service API, Scraping Bee. 
# Sign up with this link and get your own API key:
# https://www.scrapingbee.com?fpr=nobnose-inc27
api_key = "CXUWSH6Y2BRB8F07MB7YXWPYWV2TQ4K51G4N6SGEU1YDADAVDW35ZT7WNISZ8YMCQ810OP9KG22ZI2P2"`,
			shouldMatch: true,
			match:       `CXUWSH6Y2BRB8F07MB7YXWPYWV2TQ4K51G4N6SGEU1YDADAVDW35ZT7WNISZ8YMCQ810OP9KG22ZI2P2`,
		},
		{
			name: `valid_underscore`,
			data: `			gn = GoogleNews()

			# it's a fake API key, do not try to use it
			gn.top_news(scraping_bee = 'I5SYNPRFZI41WHVQWWUT0GNXFMO104343E7CXFIISR01E2V8ETSMXMJFK1XNKM7FDEEPUPRM0FYAHFF5')`,
			shouldMatch: true,
			match:       `I5SYNPRFZI41WHVQWWUT0GNXFMO104343E7CXFIISR01E2V8ETSMXMJFK1XNKM7FDEEPUPRM0FYAHFF5`,
		},
		// TODO: support this
		//		{
		//			name: `valid_js_suffix`,
		//			data: `  do {
		//  //   const apiKey = 'TQ9CDAZSORUPU1NMZXZEM11VY7K3NC3HJPBNYP2V4CZZXUY9SWEULNDHOZ77XGWO9FA9A12XWFVWUBZJ';
		//  //   const client = new scrapingbee.ScrapingBeeClient(apiKey);
		//`,
		//			shouldMatch: true,
		//			match:       `TQ9CDAZSORUPU1NMZXZEM11VY7K3NC3HJPBNYP2V4CZZXUY9SWEULNDHOZ77XGWO9FA9A12XWFVWUBZJ`,
		//		},

		// False positives
		//{
		//	name:        ``,
		//	data:        ``,
		//	shouldMatch: false,
		//},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("ScrapingBee.FromData() error = %v", err)
				return
			}

			if test.shouldMatch {
				if len(results) == 0 {
					t.Errorf("%s: did not receive a match for '%v' when one waog"+
						"s expected", test.name, test.data)
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

func TestScrapingBee_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors1")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("SCRAPINGBEE")
	inactiveSecret := testSecrets.MustGetField("SCRAPINGBEE_INACTIVE")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a scrapingbee secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_ScrapingBee,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a scrapingbee secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_ScrapingBee,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScrapingBee.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("ScrapingBee.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

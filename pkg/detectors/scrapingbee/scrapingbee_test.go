package scrapingbee

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestScrapingBee_Pattern(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// True positives
		{
			name: `valid_query_param`,
			input: ` #CHANGE API KEY TO CURRENT API KEY ON SCRAPINGBEE BELOW:
  uri = URI("https://app.scrapingbee.com/api/v1/?api_key=VNC7VJ04BQLZWL821KJ4ZLG17ON45K4Y56P59QZMDNZBWRFAS0LIK47I3KFH6AMLUXPHIUIFBDOMIOUE&url=#{url}&stealth_proxy=True&country_code=sg&wait_browser=networkidle2&json_response=True&block_resources=False&block_ads=True&js_scenario=" + CGI.escape(js_scenario))`,
			want: []string{`VNC7VJ04BQLZWL821KJ4ZLG17ON45K4Y56P59QZMDNZBWRFAS0LIK47I3KFH6AMLUXPHIUIFBDOMIOUE`},
		},
		{
			name: `valid_function_comment`,
			input: `func connectToScrapingBee() {
	// API KEY = M977YHXCMPJJ569DSB0B8KSKL9NRU2O2327MIDT55785T8LS9TJGDW4GFMCMOZNRVN3GPSXF0Y6DGC32`,
			want: []string{`M977YHXCMPJJ569DSB0B8KSKL9NRU2O2327MIDT55785T8LS9TJGDW4GFMCMOZNRVN3GPSXF0Y6DGC32`},
		},
		{
			name: `valid_csharp`,
			input: `  class test{

      string BASE_URL = @"https://app.scrapingbee.com/api/v1/";
      string API_KEY = "2OZ3HPYEUP9LVCN9TSMBEP5OU0C65AXL7MDO76VPYQNVAJW8NU0QUQQPEV7C51XQDLZUUYKZ5TAW2L85";

      public static string Get(string url)`,
			want: []string{`2OZ3HPYEUP9LVCN9TSMBEP5OU0C65AXL7MDO76VPYQNVAJW8NU0QUQQPEV7C51XQDLZUUYKZ5TAW2L85`},
		},
		{
			name: `valid_js1`,
			input: `  const options = {
    uri: "https://app.scrapingbee.com/api/v1?",
    api_key: "34TOQQ77QJALLR07ISPYL4B5EYHW3YLU5GM97GQOCA32BVW3S0S6RTVFCZGTHZ1Q5MHH1Z9GZ0B640LI",
	};`,
			want: []string{`34TOQQ77QJALLR07ISPYL4B5EYHW3YLU5GM97GQOCA32BVW3S0S6RTVFCZGTHZ1Q5MHH1Z9GZ0B640LI`},
		},
		{
			name: `valid_js2`,
			input: `  useEffect(() => {
    setLoading(true)
    base.get('https://app.scrapingbee.com/api/v1', {
params:{'api_key':'BYZCNNS0SOZCPC4EXD5SXSH0PWAXPWFMZ4SXVEQNEDMKSGBP57K31PJ44V46344XCYN7IARKQWLS0V3X',
        'url': 'https://www.flipkart.com/search?q=${searchItem}',
			'block_resources': 'false',
		}
	}).then((response) => {`,
			want: []string{`BYZCNNS0SOZCPC4EXD5SXSH0PWAXPWFMZ4SXVEQNEDMKSGBP57K31PJ44V46344XCYN7IARKQWLS0V3X`},
		},
		{
			name: `valid_js3`,
			input: `const scrapingBeeApiKey =
  "P5IS953T7OYL5KJG8J3SVPAV5VUJ49L2OXB7HIQDVL8SSG7O9A3J6DQ6CTK65KEAM7L7MQJIEW20ZOCP"; // Replace 'YOUR_SCRAPING_BEE_API_KEY' with your actual API key`,
			want: []string{`P5IS953T7OYL5KJG8J3SVPAV5VUJ49L2OXB7HIQDVL8SSG7O9A3J6DQ6CTK65KEAM7L7MQJIEW20ZOCP`},
		},
		{
			name: `valid_php`,
			input: `// Set base url & API key
$BASE_URL = "https://app.scrapingbee.com/api/v1/?";
$API_KEY = "R4EEK5MWM2GXNK1TZUU9Z0EBA29ZUW7PW12MHI4T1BHSR7GM1G37C5BL2NHLPWC0J6VOQWP5IZJ15QV8";
`,
			want: []string{`R4EEK5MWM2GXNK1TZUU9Z0EBA29ZUW7PW12MHI4T1BHSR7GM1G37C5BL2NHLPWC0J6VOQWP5IZJ15QV8`},
		},
		{
			name:  `valid_python_sdk`,
			input: `client = ScrapingBeeClient(api_key='MZ13G1AVV8C5MEYVOIMIGJEPUH0PBSJPYTCO6IUWRZS3BXNOLA4TUP27ZGQ97LS8NRBCO66WF3ZUKSFX')`,
			want:  []string{`MZ13G1AVV8C5MEYVOIMIGJEPUH0PBSJPYTCO6IUWRZS3BXNOLA4TUP27ZGQ97LS8NRBCO66WF3ZUKSFX`},
		},
		{
			name: `valid_python_sdk_newline`,
			input: `def main():
    client = ScrapingBeeClient(
        api_key='E1PJA1D78TBTM320Z8O9XS2MTWHTCL1NSJXGFKIZO6TJB4XIM94OSR6KQNU415QB97MYJEP6T3O0IWR3')`,

			want: []string{`E1PJA1D78TBTM320Z8O9XS2MTWHTCL1NSJXGFKIZO6TJB4XIM94OSR6KQNU415QB97MYJEP6T3O0IWR3`},
		},
		{
			name: `valid_python_notebook`,
			input: `   "source": [
    "Every time you call any function there is an HTTPS request to Google's servers. To prevent your servers IP address being locked by Google we should use a service that handles proxy rotation for us. In this case we are using **ScrapingBee API**.\n",
    "\n",
    "ScrapingBee API key:\n",
    "\n",
    "    QEUXIXLN8OULIISPZ1FXZUCWF7M42ZOUXRV7491R6RYQTFCSV8A4Y1B2YFPCD0HL2X62KPGTHFODSW6G\n",
    "\n",
    "NOTE: This API key is available till 08 March 2021 and expires after 200 requests  \n",
    "NOTE: **this Python package still works out of the box**."
   ]`,

			want: []string{`QEUXIXLN8OULIISPZ1FXZUCWF7M42ZOUXRV7491R6RYQTFCSV8A4Y1B2YFPCD0HL2X62KPGTHFODSW6G`},
		},
		{
			name: `valid_python_nonapiurl`,
			input: `##########################################################################################################
# We use the best scraper service API, Scraping Bee.
api_key = "CXUWSH6Y2BRB8F07MB7YXWPYWV2TQ4K51G4N6SGEU1YDADAVDW35ZT7WNISZ8YMCQ810OP9KG22ZI2P2"`,
			want: []string{`CXUWSH6Y2BRB8F07MB7YXWPYWV2TQ4K51G4N6SGEU1YDADAVDW35ZT7WNISZ8YMCQ810OP9KG22ZI2P2`},
		},
		{
			name: `valid_underscore`,
			input: `			gn = GoogleNews()

			# it's a fake API key, do not try to use it
			gn.top_news(scraping_bee = 'I5SYNPRFZI41WHVQWWUT0GNXFMO104343E7CXFIISR01E2V8ETSMXMJFK1XNKM7FDEEPUPRM0FYAHFF5')`,

			want: []string{`I5SYNPRFZI41WHVQWWUT0GNXFMO104343E7CXFIISR01E2V8ETSMXMJFK1XNKM7FDEEPUPRM0FYAHFF5`},
		},
		// TODO: support this
		//		{
		//			name: `valid_js_suffix`,
		//			input: `  do {
		//  //   const apiKey = 'TQ9CDAZSORUPU1NMZXZEM11VY7K3NC3HJPBNYP2V4CZZXUY9SWEULNDHOZ77XGWO9FA9A12XWFVWUBZJ';
		//  //   const client = new scrapingbee.ScrapingBeeClient(apiKey);
		// `,
		//
		//			want: []string{       `TQ9CDAZSORUPU1NMZXZEM11VY7K3NC3HJPBNYP2V4CZZXUY9SWEULNDHOZ77XGWO9FA9A12XWFVWUBZJ`},
		//		},

		// False positives
		{
			name:  `invalid - lowercase`,
			input: `const scrapingbeeKey = 'tq9cdazsorupu1nmzxzem11vy7k3nc3hjpbnyp2v4czzxuy9sweulndhoz77xgwo9fa9a12xwfvwubzj'`,
		},
	}

	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
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

package DetectorsV2

import "regexp"

type Detector struct {
	Name        string
	MultiCred   bool
	Credentials []Credential
}

type Credential struct {
	CredType       string
	Regex          *regexp.Regexp
	CharacterRange *Range
}

type Range struct {
	Min int
	Max int
}

type DetectorBuckets struct {
	Buckets map[int][]Detector // map of bucket number to list of detectors. Int is the regex capture group minimum length
}

func NewDetectorBuckets() *DetectorBuckets {
	detectors := simpleDetectors()
	buckets := make(map[int][]Detector)
	for _, detector := range detectors {
		for _, cred := range detector.Credentials {
			if _, ok := buckets[cred.CharacterRange.Min]; !ok {
				buckets[cred.CharacterRange.Min] = []Detector{detector}
			} else {
				buckets[cred.CharacterRange.Min] = append(buckets[cred.CharacterRange.Min], detector)
			}
		}
	}
	return &DetectorBuckets{
		Buckets: buckets,
	}
}

func (sd *DetectorBuckets) GetDetectors(wordLength int) []Detector {
	// Starting with -1 to ensure that if no bucket is found, we return an empty list
	maxKeyFound := -1
	for key := range sd.Buckets {
		// If the key is less than or equal to the word length, and it's the largest key found so far
		if key <= wordLength && key > maxKeyFound {
			maxKeyFound = key
		}
	}

	// If we've found a valid key, return its value, else return an empty list
	if maxKeyFound != -1 {
		return sd.Buckets[maxKeyFound]
	}
	return []Detector{}
}

func simpleDetectors() []Detector {
	return []Detector{

		{
			Name:      "abbysale",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "abstract",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "abuseipdb",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{80})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 80,
					},
				},
			},
		},

		{
			Name:      "accuweather",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([a-z0-9A-Z\%]{35})\b`),
					CharacterRange: &Range{
						Min: 35,
						Max: 35,
					},
				},
			},
		},

		{
			Name:      "adafruitio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(aio\_[a-zA-Z0-9]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "adobeio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9.]{12})\b`),
					CharacterRange: &Range{
						Min: 12,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "adzuna",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "aeroworkflow",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9^!]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{1,})\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "agora",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "aha",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "airbrakeprojectkey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{6})\b`),
					CharacterRange: &Range{
						Min: 6,
						Max: 6,
					},
				},
			},
		},

		{
			Name:      "airbrakeuserkey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "airship",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-zA-Z]{91})\b`),
					CharacterRange: &Range{
						Min: 91,
						Max: 91,
					},
				},
			},
		},

		{
			Name:      "airtableapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(key[a-zA-Z0-9_-]{14})\b`),
					CharacterRange: &Range{
						Min: 14,
						Max: 14,
					},
				},
			},
		},

		{
			Name:      "airvisual",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "aiven",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([a-zA-Z0-9/&#43;=]{372})`),
					CharacterRange: &Range{
						Min: 372,
						Max: 372,
					},
				},
			},
		},

		{
			Name:      "alchemy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{23}_[0-9a-zA-Z]{8})\b`),
					CharacterRange: &Range{
						Min: 23,
						Max: 23,
					},
				},
			},
		},

		{
			Name:      "alconost",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "alegra",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9.-@]{25,30})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "aletheiaapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "algoliaadminkey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{10})\b`),
					CharacterRange: &Range{
						Min: 10,
						Max: 10,
					},
				},
			},
		},

		{
			Name:      "alibaba",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b(LTAI[a-zA-Z0-9]{17,21})[\&#34;&#39;;\s]*`),
					CharacterRange: &Range{
						Min: 17,
						Max: 21,
					},
				},
			},
		},

		{
			Name:      "alienvault",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "allsports",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "amadeus",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "ambee",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "amplitudeapikey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "anypoint",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "apacta",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "api2cart",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "apideck",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sk_live_[a-z0-9A-Z-]{93})\b`),
					CharacterRange: &Range{
						Min: 93,
						Max: 93,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "apiflash",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "apifonica",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{11}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 11,
						Max: 11,
					},
				},
			},
		},

		{
			Name:      "apify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(apify\_api\_[a-zA-Z-0-9]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "apilayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "apimatic",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "apiscience",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-bA-Z0-9\S]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "apitemplate",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{39})\b`),
					CharacterRange: &Range{
						Min: 39,
						Max: 39,
					},
				},
			},
		},

		{
			Name:      "apollo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "appcues",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{5})\b`),
					CharacterRange: &Range{
						Min: 5,
						Max: 5,
					},
				},
			},
		},

		{
			Name:      "appfollow",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "appointedd",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9=&#43;]{88})`),
					CharacterRange: &Range{
						Min: 88,
						Max: 88,
					},
				},
			},
		},

		{
			Name:      "appsynergy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "apptivo",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "artifactory",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{73})`),
					CharacterRange: &Range{
						Min: 73,
						Max: 73,
					},
				},
			},
		},

		{
			Name:      "artsy",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "asanaoauth",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z\/:0-9]{51})\b`),
					CharacterRange: &Range{
						Min: 51,
						Max: 51,
					},
				},
			},
		},

		{
			Name:      "asanapersonalaccesstoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9]{1,}\/[0-9]{16,}:[A-Za-z0-9]{32,})\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "assemblyai",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "atera",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([[0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "audd",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "auth0managementapitoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`([a-zA-Z0-9\-]{2,16}\.[a-zA-Z0-9_-]{2,3}\.auth0\.com)`),
					CharacterRange: &Range{
						Min: 2,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "auth0oauth",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "IdPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{32,60})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 60,
					},
				},

				{
					CredType: "SecretPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{64,})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 768,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9][a-zA-Z0-9._-]*auth0\.com)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "autodesk",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "autoklose",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "autopilot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "avazapersonalaccesstoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9]&#43;-[0-9a-f]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "aviationstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "aws",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`[^A-Za-z0-9&#43;\/]{0,1}([A-Za-z0-9&#43;\/]{40})[^A-Za-z0-9&#43;\/]{0,1}`),
					CharacterRange: &Range{
						Min: 0,
						Max: 1,
					},
				},
			},
		},

		{
			Name:      "axonaut",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "aylien",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "ayrshare",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z]{7}-[A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7})\b`),
					CharacterRange: &Range{
						Min: 7,
						Max: 7,
					},
				},
			},
		},

		{
			Name:        "azure",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "bannerbear",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{22}tt)\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "baremetrics",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{25})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 25,
					},
				},
			},
		},

		{
			Name:      "baseapiio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "beamer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_&#43;/]{45}=)`),
					CharacterRange: &Range{
						Min: 45,
						Max: 45,
					},
				},
			},
		},

		{
			Name:      "beebole",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "besnappy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "besttime",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "billomat",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{1,})\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "bitbar",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "bitcoinaverage",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "bitfinex",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "KeyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},

				{
					CredType: "SecretPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "bitlyaccesstoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "bitmex",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([ \r\n]{1}[0-9a-zA-Z\-\_]{24}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 1,
						Max: 1,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`([ \r\n]{1}[0-9a-zA-Z\-\_]{48}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 1,
						Max: 1,
					},
				},
			},
		},

		{
			Name:      "blablabus",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "blazemeter",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "blitapp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{39})\b`),
					CharacterRange: &Range{
						Min: 39,
						Max: 39,
					},
				},
			},
		},

		{
			Name:      "blocknative",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "blogger",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z-]{39})\b`),
					CharacterRange: &Range{
						Min: 39,
						Max: 39,
					},
				},
			},
		},

		{
			Name:      "bombbomb",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-._]{704})\b`),
					CharacterRange: &Range{
						Min: 704,
						Max: 704,
					},
				},
			},
		},

		{
			Name:      "boostnote",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "borgbase",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9/_.-]{148,152})\b`),
					CharacterRange: &Range{
						Min: 148,
						Max: 152,
					},
				},
			},
		},

		{
			Name:      "braintreepayments",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "brandfetch",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "browserstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "browshot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "bscscan",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{34})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:      "buddyns",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "bugherd",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "bugsnag",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "buildkite",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "buildkite",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(bkua_[a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "bulbul",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "bulksms",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-fA-Z0-9*]{29})\b`),
					CharacterRange: &Range{
						Min: 29,
						Max: 29,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([A-F0-9-]{37})\b`),
					CharacterRange: &Range{
						Min: 37,
						Max: 37,
					},
				},
			},
		},

		{
			Name:      "buttercms",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "caflou",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-bA-Z0-9\S]{155})\b`),
					CharacterRange: &Range{
						Min: 155,
						Max: 155,
					},
				},
			},
		},

		{
			Name:      "calendarific",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "calendlyapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{20}.[a-zA-Z-0-9]{171}.[a-zA-Z-0-9_]{43})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "calorieninja",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "campayn",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "cannyio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[0-9]{4}-[a-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "capsulecrm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-._&#43;=]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "captaindata",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "projIdPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "carboninterface",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{21})\b`),
					CharacterRange: &Range{
						Min: 21,
						Max: 21,
					},
				},
			},
		},

		{
			Name:      "cashboard",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3})\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 3,
					},
				},
			},
		},

		{
			Name:      "caspio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "censys",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "centralstationcrm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "cexio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{24,27})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 27,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{24,27})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 27,
					},
				},

				{
					CredType: "userIdPat",
					Regex:    regexp.MustCompile(`\b([a-z]{2}[0-9]{9})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 2,
					},
				},
			},
		},

		{
			Name:      "chartmogul",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "chatbot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "chatfule",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{128})\b`),
					CharacterRange: &Range{
						Min: 128,
						Max: 128,
					},
				},
			},
		},

		{
			Name:      "checio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(pk_[a-z0-9]{45})\b`),
					CharacterRange: &Range{
						Min: 45,
						Max: 45,
					},
				},
			},
		},

		{
			Name:      "checklyhq",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "checkout",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b((sk_|sk_test_)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b(cus_[0-9a-zA-Z]{26})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},
			},
		},

		{
			Name:      "checkvist",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{14})\b`),
					CharacterRange: &Range{
						Min: 14,
						Max: 14,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([\w\.-]&#43;@[\w-]&#43;\.[\w\.-]{2,5})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 5,
					},
				},
			},
		},

		{
			Name:      "cicero",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "circleci",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([a-fA-F0-9]{40})`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "clarifai",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "clearbit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z_]{35})\b`),
					CharacterRange: &Range{
						Min: 35,
						Max: 35,
					},
				},
			},
		},

		{
			Name:      "clickhelp",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-z]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:        "clicksendsms",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "clickuppersonaltoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(pk_[0-9]{8}_[0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "cliengo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "clinchpad",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "clockify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "clockworksms",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "KeyPat",
					Regex:    regexp.MustCompile(`\b([0-9]{5})\b`),
					CharacterRange: &Range{
						Min: 5,
						Max: 5,
					},
				},
			},
		},

		{
			Name:      "close",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(api_[a-z0-9A-Z.]{45})\b`),
					CharacterRange: &Range{
						Min: 45,
						Max: 45,
					},
				},
			},
		},

		{
			Name:        "cloudconvert",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "cloudelements",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "cloudflareapitoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "cloudflarecakey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(v[A-Za-z0-9._-]{173,})\b`),
					CharacterRange: &Range{
						Min: 173,
						Max: 2076,
					},
				},
			},
		},

		{
			Name:      "cloudflareglobalapikey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "KeyPat",
					Regex:    regexp.MustCompile(`([A-Za-z0-9_-]{37})`),
					CharacterRange: &Range{
						Min: 37,
						Max: 37,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9&#43;._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-zA-Z0-9_-]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "cloudimage",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9_]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "cloudmersive",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "cloudplan",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "cloudsmith",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "cloverly",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9:_]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "cloze",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([\w\.-]&#43;@[\w-]&#43;\.[\w\.-]{2,5})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 5,
					},
				},
			},
		},

		{
			Name:      "clustdoc",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "codacy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "codeclimate",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:        "codemagic",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "codequiry",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "coinapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "coinbase",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "coinlayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "coinlib",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "coinmarketcap",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "collect2",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "column",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b((?:test|live)_[a-zA-Z0-9]{27})\b`),
					CharacterRange: &Range{
						Min: 27,
						Max: 27,
					},
				},
			},
		},

		{
			Name:      "commercejs",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9_]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "commodities",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "companyhub",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9$%^=-]{4,32})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "confluent",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\&#43;\/]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "contentfulpersonalaccesstoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(CFPAT-[a-zA-Z0-9_\-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "conversiontools",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9_.]{157,165})\b`),
					CharacterRange: &Range{
						Min: 157,
						Max: 165,
					},
				},
			},
		},

		{
			Name:      "convertapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "convertkit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z_]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "convier",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9]{2}\|[a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 2,
					},
				},
			},
		},

		{
			Name:      "copper",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{4,25}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 25,
					},
				},
			},
		},

		{
			Name:        "couchbase",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "countrylayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "courier",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(pk\_[a-zA-Z0-9]{1,}\_[a-zA-Z0-9]{28})\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "coveralls",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{37})\b`),
					CharacterRange: &Range{
						Min: 37,
						Max: 37,
					},
				},
			},
		},

		{
			Name:      "craftmypdf",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{35})\b`),
					CharacterRange: &Range{
						Min: 35,
						Max: 35,
					},
				},
			},
		},

		{
			Name:      "crossbrowsertesting",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{4,25}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 25,
					},
				},
			},
		},

		{
			Name:      "crowdin",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{80})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 80,
					},
				},
			},
		},

		{
			Name:      "cryptocompare",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z-0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "currencycloud",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-z]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "currencyfreaks",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "currencylayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "currencyscoop",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "currentsapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\S]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "customerguru",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "customerio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "d7network",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\W\S]{23}\=)`),
					CharacterRange: &Range{
						Min: 23,
						Max: 23,
					},
				},
			},
		},

		{
			Name:      "dailyco",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "dandelion",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "dareboost",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:        "databox",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "databrickstoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(dapi[a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "datadogtoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "datafire",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9\S]{175,190})\b`),
					CharacterRange: &Range{
						Min: 175,
						Max: 190,
					},
				},
			},
		},

		{
			Name:      "datagov",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "debounce",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{13})\b`),
					CharacterRange: &Range{
						Min: 13,
						Max: 13,
					},
				},
			},
		},

		{
			Name:      "deepai",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "deepgram",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "delighted",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "demio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{10,20})\b`),
					CharacterRange: &Range{
						Min: 10,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "deputy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "detectify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "detectlanguage",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "dfuse",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(web\_[0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "diffbot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "diggernaut",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "digitaloceantoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "digitaloceanv2",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "discordbottoken",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{17})\b`),
					CharacterRange: &Range{
						Min: 17,
						Max: 17,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "discordwebhook",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(https:\/\/discord\.com\/api\/webhooks\/[0-9]{18}\/[0-9a-zA-Z-]{68})`),
					CharacterRange: &Range{
						Min: 18,
						Max: 18,
					},
				},
			},
		},

		{
			Name:      "disqus",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "ditto",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12}\.[a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "dnscheck",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "docparser",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "documo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9]{154}.[a-zA-Z0-9_-]{43})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:        "docusign",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "doppler",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(dp\.pt\.[a-zA-Z0-9]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "dotmailer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(apiuser-[a-z0-9]{12}@apiconnector.com)\b`),
					CharacterRange: &Range{
						Min: 12,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "dovico",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32}\.[0-9a-z]{1,}\b)`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "dronahq",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "droneci",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "dropbox",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sl\.[A-Za-z0-9\-\_]{130,140})\b`),
					CharacterRange: &Range{
						Min: 130,
						Max: 140,
					},
				},
			},
		},

		{
			Name:      "duply",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7})\b`),
					CharacterRange: &Range{
						Min: 7,
						Max: 7,
					},
				},
			},
		},

		{
			Name:      "dwolla",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "dynalist",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-_]{128})\b`),
					CharacterRange: &Range{
						Min: 128,
						Max: 128,
					},
				},
			},
		},

		{
			Name:      "dyspatch",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{52})\b`),
					CharacterRange: &Range{
						Min: 52,
						Max: 52,
					},
				},
			},
		},

		{
			Name:      "eagleeyenetworks",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{15})\b`),
					CharacterRange: &Range{
						Min: 15,
						Max: 15,
					},
				},
			},
		},

		{
			Name:      "easyinsight",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-zA-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "ecostruxureit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(AK1[0-9a-zA-Z\/]{50,55})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 55,
					},
				},
			},
		},

		{
			Name:      "edamam",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "edenai",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{36}.[a-zA-Z0-9]{92}.[a-zA-Z0-9_]{43})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "eightxeight",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{18,30})\b`),
					CharacterRange: &Range{
						Min: 18,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "elasticemail",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{96})\b`),
					CharacterRange: &Range{
						Min: 96,
						Max: 96,
					},
				},
			},
		},

		{
			Name:      "enablex",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "enigma",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "etherscan",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{34})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:      "ethplorer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "etsyapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "everhour",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{4}-[0-9a-f]{4}-[0-9a-f]{6}-[0-9a-f]{6}-[0-9a-f]{8})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 4,
					},
				},
			},
		},

		{
			Name:      "exchangerateapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "exchangeratesapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "exportsdk",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{5,15}_[0-9a-z-]{36})\b`),
					CharacterRange: &Range{
						Min: 5,
						Max: 15,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "extractorapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "facebookoauth",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "IdPat",
					Regex:    regexp.MustCompile(`\b([0-9]{15,18})\b`),
					CharacterRange: &Range{
						Min: 15,
						Max: 18,
					},
				},

				{
					CredType: "SecretPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "faceplusplus",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z_-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z_-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "fakejson",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "fastforex",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "fastlypersonaltoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "feedier",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "fetchrss",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z.]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "fibery",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}.[0-9a-f]{35})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{2,40})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "figmapersonalaccesstoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9]{6}-[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 6,
						Max: 6,
					},
				},
			},
		},

		{
			Name:      "fileio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9.-]{39})\b`),
					CharacterRange: &Range{
						Min: 39,
						Max: 39,
					},
				},
			},
		},

		{
			Name:      "finage",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(API_KEY[0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "financialmodelingprep",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "findl",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "finnhub",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "fixerio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "flatio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{128})\b`),
					CharacterRange: &Range{
						Min: 128,
						Max: 128,
					},
				},
			},
		},

		{
			Name:      "fleetbase",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(flb_live_[0-9a-zA-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "flickr",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "flightapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "flightlabs",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9._-]{300,350})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:      "flightstats",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "float",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{16}[A-Za-z0-9&#43;/]{42,43}=)`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "flowdash",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "flowdock",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "flowflu",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{51})\b`),
					CharacterRange: &Range{
						Min: 51,
						Max: 51,
					},
				},
			},
		},

		{
			Name:      "flutterwave",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(FLWSECK-[0-9a-z]{32}-X)\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "fmfw",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "formbucket",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{1,}.[0-9A-Za-z]{1,}\.[0-9A-Z-a-z\-_]{1,})`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "formcraft",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "formio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[0-9A-Za-z]{310}\.[0-9A-Z-a-z\-_]{43}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 310,
						Max: 310,
					},
				},
			},
		},

		{
			Name:      "formsite",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "foursquare",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "frameio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(fio-u-[0-9a-zA-Z_-]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "freshbooks",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "uriPat",
					Regex:    regexp.MustCompile(`\b(https://www.[0-9A-Za-z_-]{1,}.com)\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "freshdesk",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "front",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{36}.[0-9a-zA-Z\.\-\_]{188,244})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "ftp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\bftp://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]&#43;\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "fulcrum",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{80})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 80,
					},
				},
			},
		},

		{
			Name:      "fullstory",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9/&#43;]{88})\b`),
					CharacterRange: &Range{
						Min: 88,
						Max: 88,
					},
				},
			},
		},

		{
			Name:      "fusebill",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{88})\b`),
					CharacterRange: &Range{
						Min: 88,
						Max: 88,
					},
				},
			},
		},

		{
			Name:      "fxmarket",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-zA-Z-_=]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "gcp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\{[^{]&#43;auth_provider_x509_cert_url[^}]&#43;\}`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "geckoboard",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{44})\b`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},
			},
		},

		{
			Name:      "gemini",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b((?:master-|account-)[0-9A-Za-z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`[A-Za-z0-9]{27,28}`),
					CharacterRange: &Range{
						Min: 27,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "generic",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(\b[\x21-\x7e]{16,64}\b)`),
					CharacterRange: &Range{
						Min: 16,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "gengo",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([ ]{0,1}[0-9a-zA-Z\[\]\-\(\)\{\}|_^@$=~]{64}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 0,
						Max: 1,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`([ ]{0,1}[0-9a-zA-Z\[\]\-\(\)\{\}|_^@$=~]{64}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 0,
						Max: 1,
					},
				},
			},
		},

		{
			Name:      "geoapify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "geocode",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "geocodify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "geocodio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{39})\b`),
					CharacterRange: &Range{
						Min: 39,
						Max: 39,
					},
				},

				{
					CredType: "searchPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\S]{7,30})\b`),
					CharacterRange: &Range{
						Min: 7,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "geoipifi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "getemail",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "getemails",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{26})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{18})\b`),
					CharacterRange: &Range{
						Min: 18,
						Max: 18,
					},
				},
			},
		},

		{
			Name:      "getgeoapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "getgist",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z&#43;=]{68})`),
					CharacterRange: &Range{
						Min: 68,
						Max: 68,
					},
				},
			},
		},

		{
			Name:      "getresponse",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "getsandbox",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{15,30})\b`),
					CharacterRange: &Range{
						Min: 15,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "github",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 255,
					},
				},
			},
		},

		{
			Name:      "github_old",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(?i)(?:github|gh|pat)[^\.].{0,40}[ =:&#39;&#34;]&#43;([a-f0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "githubapp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(-----BEGIN RSA PRIVATE KEY-----\s[A-Za-z0-9&#43;\/\s]*\s-----END RSA PRIVATE KEY-----)`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "gitlab",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b((?:glpat|)[a-zA-Z0-9\-=_]{20,22})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "gitlab",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "gitter",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "glassnode",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{27})\b`),
					CharacterRange: &Range{
						Min: 27,
						Max: 27,
					},
				},
			},
		},

		{
			Name:      "glitterlyapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "gocanvas",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z/&#43;]{43}=[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([\w\.-]&#43;@[\w-]&#43;\.[\w\.-]{2,5})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 5,
					},
				},
			},
		},

		{
			Name:      "gocardless",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(live_[0-9A-Za-z\_\-]{40}[ &#34;&#39;\r\n]{1})`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "goodday",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "graphcms",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9]{73}.ey[a-zA-Z0-9]{365}.[a-zA-Z0-9_-]{683})\b`),
					CharacterRange: &Range{
						Min: 73,
						Max: 73,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{25})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 25,
					},
				},
			},
		},

		{
			Name:      "graphhopper",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "groovehq",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{64})`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "gtmetrix",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "guardianapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "gumroad",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "guru",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "gyazo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "happi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{56})`),
					CharacterRange: &Range{
						Min: 56,
						Max: 56,
					},
				},
			},
		},

		{
			Name:      "happyscribe",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "harvest",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z._]{97})\b`),
					CharacterRange: &Range{
						Min: 97,
						Max: 97,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{4,9})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 9,
					},
				},
			},
		},

		{
			Name:      "heatmapapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "hellosign",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9/&#43;]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "helpcrunch",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9&#43;/=]{328})`),
					CharacterRange: &Range{
						Min: 328,
						Max: 328,
					},
				},
			},
		},

		{
			Name:      "helpscout",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{56})\b`),
					CharacterRange: &Range{
						Min: 56,
						Max: 56,
					},
				},
			},
		},

		{
			Name:      "hereapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\S]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "heroku",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "hive",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{17})\b`),
					CharacterRange: &Range{
						Min: 17,
						Max: 17,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "hiveage",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z\_\-]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "holidayapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "holistic",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "honeycomb",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32}|[0-9a-zA-Z]{22})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "host",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{14})\b`),
					CharacterRange: &Range{
						Min: 14,
						Max: 14,
					},
				},
			},
		},

		{
			Name:      "html2pdf",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "hubspotapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{8}\-[A-Za-z0-9]{4}\-[A-Za-z0-9]{4}\-[A-Za-z0-9]{4}\-[A-Za-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "humanity",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "hunter",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9_-]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "hybiscus",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "hypertrack",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "accPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z\_\-]{27})\b`),
					CharacterRange: &Range{
						Min: 27,
						Max: 27,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z\_\-]{54})\b`),
					CharacterRange: &Range{
						Min: 54,
						Max: 54,
					},
				},
			},
		},

		{
			Name:      "ibmclouduserkey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{44})\b`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},
			},
		},

		{
			Name:      "iconfinder",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "iexapis",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sk_[a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "iexcloud",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9_]{35})\b`),
					CharacterRange: &Range{
						Min: 35,
						Max: 35,
					},
				},
			},
		},

		{
			Name:      "imagekit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_=]{36})`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "imagga",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z=]{72})`),
					CharacterRange: &Range{
						Min: 72,
						Max: 72,
					},
				},
			},
		},

		{
			Name:      "impala",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_]{46})\b`),
					CharacterRange: &Range{
						Min: 46,
						Max: 46,
					},
				},
			},
		},

		{
			Name:      "infura",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "insightly",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "instabot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z=&#43;\/]{43}[0-9a-zA-Z&#43;\/=]{1})`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "integromat",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "intercom",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\W\S]{59}\=)`),
					CharacterRange: &Range{
						Min: 59,
						Max: 59,
					},
				},
			},
		},

		{
			Name:      "interseller",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "intrinio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{44})\b`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},
			},
		},

		{
			Name:      "invoiceocean",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "ipapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "ipgeolocation",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "ipify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "ipinfodb",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "ipquality",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "ipstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-fA-F0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "jdbc",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(?i)jdbc:[\w]{3,10}:[^\s&#34;&#39;]{0,512}`),
					CharacterRange: &Range{
						Min: 3,
						Max: 10,
					},
				},
			},
		},

		{
			Name:        "mysql",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:        "postgres",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:        "sqlite",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:        "sqlserver",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "jiratoken",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{5,24}\.[a-zA-Z-0-9]{3,16}\.[a-zA-Z-0-9]{3,16})\b`),
					CharacterRange: &Range{
						Min: 5,
						Max: 24,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b[A-Za-z0-9._%&#43;-]&#43;@[A-Za-z0-9.-]&#43;\.[A-Z|a-z]{2,}\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "jotform",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "jumpcloud",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "juro",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "kanban",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{12})\b`),
					CharacterRange: &Range{
						Min: 12,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "kanbantool",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{12})\b`),
					CharacterRange: &Range{
						Min: 12,
						Max: 12,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{2,22})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "karmacrm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "keenio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "kickbox",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]&#43;[a-zA-Z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "klipfolio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "knapsackpro",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "kontent",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "kraken",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z\/\&#43;=]{56}[ &#34;&#39;\r\n]{1})`),
					CharacterRange: &Range{
						Min: 56,
						Max: 56,
					},
				},

				{
					CredType: "KeyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z\/\&#43;=]{86,88}[ &#34;&#39;\r\n]{1})`),
					CharacterRange: &Range{
						Min: 86,
						Max: 88,
					},
				},
			},
		},

		{
			Name:      "kucoin",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "kylas",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "languagelayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "lastfm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "launchdarkly",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "ldap",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "uriPat",
					Regex:    regexp.MustCompile(`\b(?i)ldaps?://[\S]&#43;\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "leadfeeder",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "lemlist",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "lendflow",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{36}\.[a-zA-Z0-9]{235}\.[a-zA-Z0-9]{32}\-[a-zA-Z0-9]{47}\-[a-zA-Z0-9_]{162}\-[a-zA-Z0-9]{42}\-[a-zA-Z0-9_]{40}\-[a-zA-Z0-9_]{66}\-[a-zA-Z0-9_]{59}\-[a-zA-Z0-9]{7}\-[a-zA-Z0-9_]{220})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "lessannoyingcrm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{57})\b`),
					CharacterRange: &Range{
						Min: 57,
						Max: 57,
					},
				},
			},
		},

		{
			Name:      "lexigram",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\S]{301})\b`),
					CharacterRange: &Range{
						Min: 301,
						Max: 301,
					},
				},
			},
		},

		{
			Name:      "linearapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(lin_api_[0-9A-Za-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "linemessaging",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9&#43;/]{171,172})\b`),
					CharacterRange: &Range{
						Min: 171,
						Max: 172,
					},
				},
			},
		},

		{
			Name:      "linenotify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "linkpreview",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "liveagent",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "livestorm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(eyJhbGciOiJIUzI1NiJ9\.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi[0-9A-Z-a-z]{134}\.[0-9A-Za-z\-\_]{43}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 134,
						Max: 134,
					},
				},
			},
		},

		{
			Name:      "loadmill",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "lob",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "locationiq",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(pk\.[a-zA-Z-0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "loginradius",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "lokalisetoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "loyverse",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9-a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "lunchmoney",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "luno",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{13})\b`),
					CharacterRange: &Range{
						Min: 13,
						Max: 13,
					},
				},
			},
		},

		{
			Name:      "m3o",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "macaddress",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "madkudu",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "magicbell",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9&#43;._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-zA-Z0-9_-]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "magnetic",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "mailboxlayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "mailchimp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "mailerlite",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:        "mailgun",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "mailjetbasicauth",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{87}\=)`),
					CharacterRange: &Range{
						Min: 87,
						Max: 87,
					},
				},
			},
		},

		{
			Name:      "mailjetsms",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "mailmodo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7})\b`),
					CharacterRange: &Range{
						Min: 7,
						Max: 7,
					},
				},
			},
		},

		{
			Name:      "mailsac",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(k_[0-9A-Za-z]{36,})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 432,
					},
				},
			},
		},

		{
			Name:      "mandrill",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "manifest",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "mapbox",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`([a-zA-Z-0-9]{4,32})`),
					CharacterRange: &Range{
						Min: 4,
						Max: 32,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sk\.[a-zA-Z-0-9\.]{80,240})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 240,
					},
				},
			},
		},

		{
			Name:      "mapquest",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "marketstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "mattermostpersonaltoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{26})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},
			},
		},

		{
			Name:      "mavenlink",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "maxmindlicense",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{2,7})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 7,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "meaningcloud",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "mediastack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "meistertask",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "mesibo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "messagebird",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{25})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 25,
					},
				},
			},
		},

		{
			Name:      "metaapi",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "spellPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "metrilo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "microsoftteamswebhook",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(https:\/\/[a-zA-Z-0-9]&#43;\.webhook\.office\.com\/webhookb2\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\@[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\/IncomingWebhook\/[a-zA-Z-0-9]{32}\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12})`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:        "midise",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "mindmeister",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "miro",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{27})\b`),
					CharacterRange: &Range{
						Min: 27,
						Max: 27,
					},
				},
			},
		},

		{
			Name:      "mite",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "mixmax",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "mixpanel",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9.-]{30,40})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "mockaroo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "moderation",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{36}\.[a-zA-Z0-9]{115}\.[a-zA-Z0-9_]{43})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "monday",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9_.]{210,225})\b`),
					CharacterRange: &Range{
						Min: 210,
						Max: 225,
					},
				},
			},
		},

		{
			Name:      "mongodb",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(mongodb(\&#43;srv)?://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]&#43;)\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "monkeylearn",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "moonclerk",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "moosend",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "moralis",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "mrticktock",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-z]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},

				{
					CredType: "pwordPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9!=@#$%()_^]{1,50})`),
					CharacterRange: &Range{
						Min: 1,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "mux",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`([ \r\n]{0,1}[0-9A-Za-z\/\&#43;]{75}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 0,
						Max: 1,
					},
				},
			},
		},

		{
			Name:      "myfreshworks",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-_]{2,20})\b`),
					CharacterRange: &Range{
						Min: 2,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "myintervals",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{11})\b`),
					CharacterRange: &Range{
						Min: 11,
						Max: 11,
					},
				},
			},
		},

		{
			Name:      "nasdaqdatalink",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "nethunt",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-\S]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9.-@]{25,30})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "netlify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{43,45})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 45,
					},
				},
			},
		},

		{
			Name:      "neutrinoapi",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{6,24})\b`),
					CharacterRange: &Range{
						Min: 6,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "newrelicpersonalapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_\.]{4}-[A-Za-z0-9_\.]{42})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 4,
					},
				},
			},
		},

		{
			Name:      "newsapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "newscatcher",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "nexmoapikey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "nftport",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "ngc",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([[:alnum:]]{26}:[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([[:alnum:]]{84})\b`),
					CharacterRange: &Range{
						Min: 84,
						Max: 84,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([[:alnum:]]{26}:[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},
			},
		},

		{
			Name:      "nicereply",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "nightfall",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(NF\-[a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "nimble",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "nitro",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "noticeable",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "notion",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(secret_[A-Za-z0-9]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "nozbeteams",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{16}_[0-9A-Za-z\-_]{64}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "npmtoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "npmtokenv2",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(npm_[0-9a-zA-Z]{36})`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "nugetapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{46})\b`),
					CharacterRange: &Range{
						Min: 46,
						Max: 46,
					},
				},
			},
		},

		{
			Name:      "numverify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "nutritionix",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "nylas",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "nytimes",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "oanda",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "okta",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`[a-z0-9-]{1,40}\.okta(?:preview|-emea){0,1}\.com`),
					CharacterRange: &Range{
						Min: 1,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "omnisend",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{75})\b`),
					CharacterRange: &Range{
						Min: 75,
						Max: 75,
					},
				},
			},
		},

		{
			Name:      "onedesk",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-z]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},

				{
					CredType: "pwordPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9!=@#$%^]{8,64})`),
					CharacterRange: &Range{
						Min: 8,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "onelogin",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "IDPat",
					Regex:    regexp.MustCompile(`(?i)id[a-zA-Z0-9_&#39; &#34;=]{0,20}([a-z0-9]{64})`),
					CharacterRange: &Range{
						Min: 0,
						Max: 20,
					},
				},

				{
					CredType: "SecretPat",
					Regex:    regexp.MustCompile(`(?i)secret[a-zA-Z0-9_&#39; &#34;=]{0,20}([a-z0-9]{64})`),
					CharacterRange: &Range{
						Min: 0,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "onepagecrm",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9=]{44})`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:        "onesignal",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "onwaterio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "oopspam",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "openai",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sk-[[:alnum:]]{20}T3BlbkFJ[[:alnum:]]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "opencagedata",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "opengraphr",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-zA-Z]{80})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 80,
					},
				},
			},
		},

		{
			Name:      "openuv",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "openweather",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "opsgenie",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "optimizely",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z-:]{54})\b`),
					CharacterRange: &Range{
						Min: 54,
						Max: 54,
					},
				},
			},
		},

		{
			Name:      "owlbot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "packagecloud",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "pagerdutyapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z]{1}\&#43;[a-zA-Z]{9}\-[a-z]{2}\-[a-z0-9]{5})\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 1,
					},
				},
			},
		},

		{
			Name:      "pandadoc",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "pandascore",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([ \r\n]{0,1}[0-9A-Za-z\-\_]{51}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 0,
						Max: 1,
					},
				},
			},
		},

		{
			Name:      "paperform",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-._]{850,1000})\b`),
					CharacterRange: &Range{
						Min: 850,
						Max: 1000,
					},
				},
			},
		},

		{
			Name:      "paralleldots",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "parsehub",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{12})\b`),
					CharacterRange: &Range{
						Min: 12,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "parsers",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "parseur",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "partnerstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "passbase",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{128})\b`),
					CharacterRange: &Range{
						Min: 128,
						Max: 128,
					},
				},
			},
		},

		{
			Name:      "pastebin",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "paydirtapp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "paymoapp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{44})\b`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},
			},
		},

		{
			Name:      "paymongo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "paypaloauth",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_\.]{7}-[A-Za-z0-9_\.]{72})\b`),
					CharacterRange: &Range{
						Min: 7,
						Max: 7,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_\.]{69}-[A-Za-z0-9_\.]{10})\b`),
					CharacterRange: &Range{
						Min: 69,
						Max: 69,
					},
				},
			},
		},

		{
			Name:      "paystack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sk\_[a-z]{1,}\_[A-Za-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "pdflayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "pdfshift",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "peopledatalabs",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "pepipost",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "percy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\bPERCY_TOKEN=([0-9Aa-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "pinata",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "pipedream",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "pipedrive",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "pivotaltracker",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([a-z0-9]{32})`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "pixabay",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{34})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:      "plaidkey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "planviewleankit",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{128})\b`),
					CharacterRange: &Range{
						Min: 128,
						Max: 128,
					},
				},

				{
					CredType: "DomainPat",
					Regex:    regexp.MustCompile(`(?:subdomain).\b([a-zA-Z][a-zA-Z0-9.-]{1,23}[a-zA-Z0-9])\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 23,
					},
				},
			},
		},

		{
			Name:      "planyo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{62})\b`),
					CharacterRange: &Range{
						Min: 62,
						Max: 62,
					},
				},
			},
		},

		{
			Name:      "plivo",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([A-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "podio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([[0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "pollsapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "poloniex",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{128})\b`),
					CharacterRange: &Range{
						Min: 128,
						Max: 128,
					},
				},
			},
		},

		{
			Name:      "polygon",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "positionstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "postageapp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "postbacks",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "posthog",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(phc_[a-zA-Z0-9_]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "postman",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(PMAK-[a-zA-Z-0-9]{59})\b`),
					CharacterRange: &Range{
						Min: 59,
						Max: 59,
					},
				},
			},
		},

		{
			Name:      "postmark",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "powrbot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "prefect",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(pnu_[a-zA-Z0-9]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:        "cracker",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:        "fingerprint",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:        "normalize",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "privatekey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "prodpad",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "prospectcrm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "prospectio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "protocolsio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "proxycrawl",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:        "pubnubpublishkey",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "pubnubsubscriptionkey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sub-c-[0-9a-z]{8}-[a-z]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "pulumi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(pul-[a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "purestake",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "pushbulletapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_\.]{34})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:      "pusherchannelkey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "IdPat",
					Regex:    regexp.MustCompile(`\b([0-9]{7})\b`),
					CharacterRange: &Range{
						Min: 7,
						Max: 7,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "qase",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "qualaroo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z=]{64})`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "qubole",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "quickmetrics",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "rabbitmq",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(?:amqp:)?\/\/[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]&#43;\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "rapidapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_-]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "raven",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9-]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "rawg",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "razorpay",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(?i)\brzp_live_\w{10,20}\b`),
					CharacterRange: &Range{
						Min: 10,
						Max: 20,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`([A-Za-z0-9]{20,50})`),
					CharacterRange: &Range{
						Min: 20,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "reachmail",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-_]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "readme",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(rdme_[a-z0-9]{70})`),
					CharacterRange: &Range{
						Min: 70,
						Max: 70,
					},
				},
			},
		},

		{
			Name:      "reallysimplesystems",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9-._]{153}.ey[a-zA-Z0-9-._]{916,1000})\b`),
					CharacterRange: &Range{
						Min: 153,
						Max: 153,
					},
				},
			},
		},

		{
			Name:      "rebrandly",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:        "rechargepayments",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "redis",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\bredis://[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]&#43;\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "refiner",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "rentman",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9._-]{250,300})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:      "repairshopr",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{51})\b`),
					CharacterRange: &Range{
						Min: 51,
						Max: 51,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_.!&#43;$#^*]{3,32})\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "restpack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "restpackhtmltopdfapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "restpackscreenshotapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "rev",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "KeyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z\/\&#43;]{27}\=[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 27,
						Max: 27,
					},
				},

				{
					CredType: "KeyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z\-]{27}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 27,
						Max: 27,
					},
				},
			},
		},

		{
			Name:      "revampcrm",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40}\b)`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9.-@]{25,30})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "ringcentral",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_-]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},

				{
					CredType: "uriPat",
					Regex:    regexp.MustCompile(`\b(https://www.[0-9A-Za-z_-]{1,}.com)\b`),
					CharacterRange: &Range{
						Min: 1,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "ritekit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{44})\b`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},
			},
		},

		{
			Name:      "roaring",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "clientPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_-]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_-]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "rocketreach",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{39})\b`),
					CharacterRange: &Range{
						Min: 39,
						Max: 39,
					},
				},
			},
		},

		{
			Name:      "rockset",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "roninapp",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{26})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-zA-Z]{3,32})\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "route4me",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "rownd",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{18})\b`),
					CharacterRange: &Range{
						Min: 18,
						Max: 18,
					},
				},
			},
		},

		{
			Name:      "rubygems",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(rubygems_[a-zA0-9]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "runrunit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "salesblink",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "salescookie",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "salesflare",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{45})\b`),
					CharacterRange: &Range{
						Min: 45,
						Max: 45,
					},
				},
			},
		},

		{
			Name:      "salesmate",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{3,22})\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "satismeterprojectkey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{4,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,12})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "satismeterwritekey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "saucelabs",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b(oauth\-[a-z0-9]{8,}\-[a-z0-9]{5})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 96,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "scalewaykey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "scalr",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z._]{136})`),
					CharacterRange: &Range{
						Min: 136,
						Max: 136,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{4,50})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "scrapeowl",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "scraperapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "scraperbox",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "scrapersite",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{45})\b`),
					CharacterRange: &Range{
						Min: 45,
						Max: 45,
					},
				},
			},
		},

		{
			Name:      "scrapestack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "scrapfly",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32}|scp-(?:live|test)-[a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "scrapingant",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "scrapingbee",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{80})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 80,
					},
				},
			},
		},

		{
			Name:      "screenshotapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{7}\-[0-9A-Z]{7}\-[0-9A-Z]{7}\-[0-9A-Z]{7})\b`),
					CharacterRange: &Range{
						Min: 7,
						Max: 7,
					},
				},
			},
		},

		{
			Name:      "screenshotlayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "scrutinizerci",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "securitytrails",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "segmentapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9_\-a-zA-Z]{43}\.[A-Za-z0-9_\-a-zA-Z]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "selectpdf",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "semaphore",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "sendbird",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},

				{
					CredType: "IdPat",
					Regex:    regexp.MustCompile(`\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "sendbirdorganizationapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "sendgrid",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(SG\.[\w\-_]{20,24}\.[\w\-_]{39,50})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "sendinbluev2",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(xkeysib\-[A-Za-z0-9_-]{81})\b`),
					CharacterRange: &Range{
						Min: 81,
						Max: 81,
					},
				},
			},
		},

		{
			Name:      "sentiment",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9]{17})\b`),
					CharacterRange: &Range{
						Min: 17,
						Max: 17,
					},
				},
			},
		},

		{
			Name:      "sentrytoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "serphouse",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "serpstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "sheety",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "sherpadesk",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "shipday",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9.]{11}[a-zA-Z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 11,
						Max: 11,
					},
				},
			},
		},

		{
			Name:      "shodankey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "shopify",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(shppa_|shpat_)([0-9A-Fa-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`[a-zA-Z0-9-]&#43;\.myshopify\.com`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},
			},
		},

		{
			Name:      "shortcut",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "shotstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "shutterstock",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{16})\b`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "shutterstockoauth",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(v2/[0-9A-Za-z]{388})\b`),
					CharacterRange: &Range{
						Min: 388,
						Max: 388,
					},
				},
			},
		},

		{
			Name:      "signable",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "signalwire",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "signaturit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{86})\b`),
					CharacterRange: &Range{
						Min: 86,
						Max: 86,
					},
				},
			},
		},

		{
			Name:      "signupgenius",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "sigopt",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "simfin",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "simplesat",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{40})`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "simplynoted",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\S]{340,360})\b`),
					CharacterRange: &Range{
						Min: 340,
						Max: 360,
					},
				},
			},
		},

		{
			Name:      "simvoly",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{33})\b`),
					CharacterRange: &Range{
						Min: 33,
						Max: 33,
					},
				},
			},
		},

		{
			Name:      "sinchmessage",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "sirv",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9\S]{88})`),
					CharacterRange: &Range{
						Min: 88,
						Max: 88,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{26})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},
			},
		},

		{
			Name:      "siteleaf",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "skrappio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{42})\b`),
					CharacterRange: &Range{
						Min: 42,
						Max: 42,
					},
				},
			},
		},

		{
			Name:      "skybiometry",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{25,26})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 26,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{25,26})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 26,
					},
				},
			},
		},

		{
			Name:        "slack",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "slackwebhook",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]&#43;/B[A-Z0-9]&#43;/[A-Za-z0-9]{23,25})`),
					CharacterRange: &Range{
						Min: 23,
						Max: 25,
					},
				},
			},
		},

		{
			Name:      "smartsheets",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{37})\b`),
					CharacterRange: &Range{
						Min: 37,
						Max: 37,
					},
				},
			},
		},

		{
			Name:      "smartystreets",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "smooch",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(act_[0-9a-z]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z_-]{86})\b`),
					CharacterRange: &Range{
						Min: 86,
						Max: 86,
					},
				},
			},
		},

		{
			Name:      "snipcart",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_]{75})\b`),
					CharacterRange: &Range{
						Min: 75,
						Max: 75,
					},
				},
			},
		},

		{
			Name:      "snykkey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "sonarcloud",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "sparkpost",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:        "speechtextai",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "splunkobservabilitytoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "spoonacular",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "sportradar",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "sportsmonk",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "spotifykey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:        "sqlserver",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "square",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`(EAAA[a-zA-Z0-9\-\&#43;\=]{60})`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "squareapp",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`[\w\-]*sq0i[a-z]{2}-[0-9A-Za-z\-_]{22,43}`),
					CharacterRange: &Range{
						Min: 2,
						Max: 2,
					},
				},

				{
					CredType: "secPat",
					Regex:    regexp.MustCompile(`[\w\-]*sq0c[a-z]{2}-[0-9A-Za-z\-_]{40,50}`),
					CharacterRange: &Range{
						Min: 2,
						Max: 2,
					},
				},
			},
		},

		{
			Name:      "squarespace",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "squareup",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sq0idp-[0-9A-Za-z]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "sslmate",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "statuscake",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "statuspage",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "statuspal",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "stitchdata",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z_]{35})\b`),
					CharacterRange: &Range{
						Min: 35,
						Max: 35,
					},
				},
			},
		},

		{
			Name:      "stockdata",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "storecove",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_-]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "stormboard",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "stormglass",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z-]{73})\b`),
					CharacterRange: &Range{
						Min: 73,
						Max: 73,
					},
				},
			},
		},

		{
			Name:      "storyblok",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{22}t{2})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "storychief",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_\-.]{940,1000})`),
					CharacterRange: &Range{
						Min: 940,
						Max: 1000,
					},
				},
			},
		},

		{
			Name:      "strava",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{5})\b`),
					CharacterRange: &Range{
						Min: 5,
						Max: 5,
					},
				},

				{
					CredType: "secretPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "streak",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:        "stripe",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "stytch",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-_]{47}=)`),
					CharacterRange: &Range{
						Min: 47,
						Max: 47,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{49})\b`),
					CharacterRange: &Range{
						Min: 49,
						Max: 49,
					},
				},
			},
		},

		{
			Name:      "sugester",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_.!&#43;$#^*%]{3,32})\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "sumologickey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{14})\b`),
					CharacterRange: &Range{
						Min: 14,
						Max: 14,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "supabasetoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sbp_[a-z0-9]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "supernotesapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`([ \r\n]{0,1}[0-9A-Za-z\-_]{43}[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 0,
						Max: 1,
					},
				},
			},
		},

		{
			Name:      "surveyanyplace",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "surveybot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9-]{80})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 80,
					},
				},
			},
		},

		{
			Name:      "surveysparrow",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-_]{88})\b`),
					CharacterRange: &Range{
						Min: 88,
						Max: 88,
					},
				},
			},
		},

		{
			Name:      "survicate",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "swell",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{6,24})\b`),
					CharacterRange: &Range{
						Min: 6,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "swiftype",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-z-0-9]{6}\_[a-zA-z-0-9]{6}\-[a-zA-z-0-9]{6})\b`),
					CharacterRange: &Range{
						Min: 6,
						Max: 6,
					},
				},
			},
		},

		{
			Name:      "tallyfy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{36}\.[0-9A-Za-z]{264}\.[0-9A-Za-z\-\_]{683})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "tatumio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "taxjar",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "teamgate",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{80})\b`),
					CharacterRange: &Range{
						Min: 80,
						Max: 80,
					},
				},
			},
		},

		{
			Name:      "teamworkcrm",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(tkn\.v1_[0-9A-Za-z]{71}=[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 71,
						Max: 71,
					},
				},
			},
		},

		{
			Name:      "teamworkdesk",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(tkn\.v1_[0-9A-Za-z]{71}=[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 71,
						Max: 71,
					},
				},
			},
		},

		{
			Name:      "teamworkspaces",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(tkn\.v1_[0-9A-Za-z]{71}=[ \r\n]{1})`),
					CharacterRange: &Range{
						Min: 71,
						Max: 71,
					},
				},
			},
		},

		{
			Name:      "technicalanalysisapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{48})\b`),
					CharacterRange: &Range{
						Min: 48,
						Max: 48,
					},
				},
			},
		},

		{
			Name:      "tefter",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "telegrambottoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 10,
					},
				},
			},
		},

		{
			Name:      "teletype",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z-]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "telnyx",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(KEY[0-9A-Za-z_-]{55})\b`),
					CharacterRange: &Range{
						Min: 55,
						Max: 55,
					},
				},
			},
		},

		{
			Name:      "terraformcloudpersonaltoken",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67})\b`),
					CharacterRange: &Range{
						Min: 14,
						Max: 14,
					},
				},
			},
		},

		{
			Name:      "testingbot",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "text2data",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "textmagic",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "theoddsapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "thinkific",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "domainPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{4,40})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "thousandeyes",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "ticketmaster",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "tickettailor",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(sk[a-fA-Z0-9_]{45})\b`),
					CharacterRange: &Range{
						Min: 45,
						Max: 45,
					},
				},
			},
		},

		{
			Name:      "tiingo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "timecamp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{26})\b`),
					CharacterRange: &Range{
						Min: 26,
						Max: 26,
					},
				},
			},
		},

		{
			Name:      "timezoneapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "tineswebhook",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(https://[\w-]&#43;\.tines\.com/webhook/[a-z0-9]{32}/[a-z0-9]{32})`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "tly",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "tmetric",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "todoist",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "toggltrack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "tokeet",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9]{10}.[0-9]{4})\b`),
					CharacterRange: &Range{
						Min: 10,
						Max: 10,
					},
				},
			},
		},

		{
			Name:      "tomorrowio",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "tomtom",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-zA-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "tradier",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{28})\b`),
					CharacterRange: &Range{
						Min: 28,
						Max: 28,
					},
				},
			},
		},

		{
			Name:      "transferwise",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f-]{8}-[0-9a-f-]{4}-[0-9a-f-]{4}-[0-9a-f-]{4}-[0-9a-f-]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "travelpayouts",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "travisci",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9A-Z_]{22})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "trelloapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "tru",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "twelvedata",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "twilio",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\bAC[0-9a-f]{32}\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b[0-9a-f]{32}\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "twist",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f:]{40,47})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 47,
					},
				},
			},
		},

		{
			Name:      "twitch",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "twitter",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z]{22}%[a-zA-Z-0-9]{23}%[a-zA-Z-0-9]{6}%[a-zA-Z-0-9]{3}%[a-zA-Z-0-9]{9}%[a-zA-Z-0-9]{52})\b`),
					CharacterRange: &Range{
						Min: 22,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "tyntec",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "typeform",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{44})\b`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},
			},
		},

		{
			Name:      "typetalk",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "ubidots",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(BBFF-[0-9a-zA-Z]{30})\b`),
					CharacterRange: &Range{
						Min: 30,
						Max: 30,
					},
				},
			},
		},

		{
			Name:      "uclassify",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{12})\b`),
					CharacterRange: &Range{
						Min: 12,
						Max: 12,
					},
				},
			},
		},

		{
			Name:      "unifyid",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_=-]{44})`),
					CharacterRange: &Range{
						Min: 44,
						Max: 44,
					},
				},
			},
		},

		{
			Name:      "unplugg",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "unsplash",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z_]{43})\b`),
					CharacterRange: &Range{
						Min: 43,
						Max: 43,
					},
				},
			},
		},

		{
			Name:      "upcdatabase",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "uplead",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "uploadcare",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},

				{
					CredType: "publicKeyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{20})\b`),
					CharacterRange: &Range{
						Min: 20,
						Max: 20,
					},
				},
			},
		},

		{
			Name:      "uptimerobot",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{9}-[a-zA-Z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 9,
						Max: 9,
					},
				},
			},
		},

		{
			Name:      "upwave",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "uri",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(?:https?:)?\/\/[\S]{3,50}:([\S]{3,50})@[-.%\w\/:]&#43;\b`),
					CharacterRange: &Range{
						Min: 3,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "urlscan",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "user",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-._&#43;=]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "userflow",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z_]{29})\b`),
					CharacterRange: &Range{
						Min: 29,
						Max: 29,
					},
				},
			},
		},

		{
			Name:      "userstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "vatlayer",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "vbout",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9]{25})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 25,
					},
				},
			},
		},

		{
			Name:      "vercel",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "verifier",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{96})\b`),
					CharacterRange: &Range{
						Min: 96,
						Max: 96,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9-]{5,16}\@[a-zA-Z-0-9]{4,16}\.[a-zA-Z-0-9]{3,6})\b`),
					CharacterRange: &Range{
						Min: 5,
						Max: 16,
					},
				},
			},
		},

		{
			Name:      "verimail",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "veriphone",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "versioneye",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "viewneo",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{120,300}.[a-z0-9A-Z]{150,300}.[a-z0-9A-Z-_]{600,800})`),
					CharacterRange: &Range{
						Min: 120,
						Max: 300,
					},
				},
			},
		},

		{
			Name:      "virustotal",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "visualcrossing",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Z]{25})\b`),
					CharacterRange: &Range{
						Min: 25,
						Max: 25,
					},
				},
			},
		},

		{
			Name:      "voicegain",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[0-9a-zA-Z_-]{34}.ey[0-9a-zA-Z_-]{108}.[0-9a-zA-Z_-]{43})\b`),
					CharacterRange: &Range{
						Min: 34,
						Max: 34,
					},
				},
			},
		},

		{
			Name:      "voodoosms",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z]{46})\b`),
					CharacterRange: &Range{
						Min: 46,
						Max: 46,
					},
				},
			},
		},

		{
			Name:      "vouchery",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "vpnapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "vultrapikey",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(` \b([A-Z0-9]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "vyte",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{50})\b`),
					CharacterRange: &Range{
						Min: 50,
						Max: 50,
					},
				},
			},
		},

		{
			Name:      "walkscore",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "weatherbit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "weatherstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "webex",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-f0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b(C[a-f0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "webflow",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "webscraper",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "webscraping",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "websitepulse",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([0-9a-zA-Z._]{4,22})\b`),
					CharacterRange: &Range{
						Min: 4,
						Max: 22,
					},
				},
			},
		},

		{
			Name:      "wepay",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "IDPat",
					Regex:    regexp.MustCompile(`\b(\d{6})\b`),
					CharacterRange: &Range{
						Min: 6,
						Max: 6,
					},
				},

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_?]{62})\b`),
					CharacterRange: &Range{
						Min: 62,
						Max: 62,
					},
				},
			},
		},

		{
			Name:      "whoxy",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{33})\b`),
					CharacterRange: &Range{
						Min: 33,
						Max: 33,
					},
				},
			},
		},

		{
			Name:      "wistia",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "wit",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "worksnaps",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9A-Za-z]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "workstack",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9Aa-zA-Z]{60})\b`),
					CharacterRange: &Range{
						Min: 60,
						Max: 60,
					},
				},
			},
		},

		{
			Name:      "worldcoinindex",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{35})\b`),
					CharacterRange: &Range{
						Min: 35,
						Max: 35,
					},
				},
			},
		},

		{
			Name:      "worldweather",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{31})\b`),
					CharacterRange: &Range{
						Min: 31,
						Max: 31,
					},
				},
			},
		},

		{
			Name:      "wrike",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b(ey[a-zA-Z0-9-._]{333})\b`),
					CharacterRange: &Range{
						Min: 333,
						Max: 333,
					},
				},
			},
		},

		{
			Name:      "yandex",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9A-Z.]{83})\b`),
					CharacterRange: &Range{
						Min: 83,
						Max: 83,
					},
				},
			},
		},

		{
			Name:      "yelp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9_\\=\.\-]{128})\b`),
					CharacterRange: &Range{
						Min: 128,
						Max: 128,
					},
				},
			},
		},

		{
			Name:      "youneedabudget",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "yousign",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "youtubeapikey",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9_]{39})\b`),
					CharacterRange: &Range{
						Min: 39,
						Max: 39,
					},
				},

				{
					CredType: "idPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z-0-9]{24})\b`),
					CharacterRange: &Range{
						Min: 24,
						Max: 24,
					},
				},
			},
		},

		{
			Name:      "zapierwebhook",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`(https:\/\/hooks\.zapier\.com\/hooks\/catch\/[A-Za-z0-9\/]{16})`),
					CharacterRange: &Range{
						Min: 16,
						Max: 16,
					},
				},
			},
		},

		{
			Name:        "zendeskapi",
			MultiCred:   false,
			Credentials: []Credential{},
		},

		{
			Name:      "zenkitapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{8}\-[0-9A-Za-z]{32})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "zenrows",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{40})\b`),
					CharacterRange: &Range{
						Min: 40,
						Max: 40,
					},
				},
			},
		},

		{
			Name:      "zenscrape",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "zenserp",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z-]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:      "zeplin",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9-.]{350,400})\b`),
					CharacterRange: &Range{
						Min: 350,
						Max: 400,
					},
				},
			},
		},

		{
			Name:      "zerobounce",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-z0-9]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},
			},
		},

		{
			Name:      "zipapi",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-z]{32})\b`),
					CharacterRange: &Range{
						Min: 32,
						Max: 32,
					},
				},

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-z]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},

				{
					CredType: "pwordPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9!=@#$%^]{7,})`),
					CharacterRange: &Range{
						Min: 7,
						Max: 84,
					},
				},
			},
		},

		{
			Name:      "zipbooks",
			MultiCred: true,
			Credentials: []Credential{

				{
					CredType: "emailPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9._-]&#43;@[a-zA-Z0-9._-]&#43;\.[a-z]&#43;)\b`),
					CharacterRange: &Range{
						Min: 0,
						Max: 0,
					},
				},

				{
					CredType: "pwordPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9!=@#$%^]{8,})`),
					CharacterRange: &Range{
						Min: 8,
						Max: 96,
					},
				},
			},
		},

		{
			Name:      "zipcodeapi",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([a-zA-Z0-9]{64})\b`),
					CharacterRange: &Range{
						Min: 64,
						Max: 64,
					},
				},
			},
		},

		{
			Name:      "zipcodebase",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
					CharacterRange: &Range{
						Min: 8,
						Max: 8,
					},
				},
			},
		},

		{
			Name:      "zonkafeedback",
			MultiCred: false,
			Credentials: []Credential{

				{
					CredType: "keyPat",
					Regex:    regexp.MustCompile(`\b([A-Za-z0-9]{36})\b`),
					CharacterRange: &Range{
						Min: 36,
						Max: 36,
					},
				},
			},
		},

		{
			Name:        "zulipchat",
			MultiCred:   false,
			Credentials: []Credential{},
		},
	}
}

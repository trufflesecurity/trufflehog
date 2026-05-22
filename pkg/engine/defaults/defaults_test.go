package defaults

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestDefaultDetectorsHaveUniqueVersions(t *testing.T) {
	detectorTypeToVersions := make(map[detector_typepb.DetectorType]map[int]struct{})
	addVersion := func(versions map[int]struct{}, version int) map[int]struct{} {
		if versions == nil {
			versions = make(map[int]struct{})
		}
		versions[version] = struct{}{}
		return versions
	}
	// Loop through all our default detectors and find the ones that
	// implement Versioner. Of those, check each version number is unique.
	for _, detector := range DefaultDetectors() {
		v, ok := detector.(detectors.Versioner)
		if !ok {
			continue
		}
		version := v.Version()
		key := detector.Type()
		if set, ok := detectorTypeToVersions[key]; ok && set != nil {
			if _, ok := set[version]; ok {
				t.Errorf("detector %q has duplicate version: %d", detector_typepb.DetectorType_name[int32(key)], version)
			}
		}
		detectorTypeToVersions[key] = addVersion(detectorTypeToVersions[key], version)
	}
}

func TestDefaultDetectorTypesImplementing(t *testing.T) {
	isVersioner := DefaultDetectorTypesImplementing[detectors.Versioner]()
	for _, detector := range DefaultDetectors() {
		_, expectedOk := detector.(detectors.Versioner)
		_, gotOk := isVersioner[detector.Type()]
		if expectedOk == gotOk {
			continue
		}
		t.Errorf(
			"detector %q doesn't match expected",
			detector_typepb.DetectorType_name[int32(detector.Type())],
		)
	}
}

func TestDefaultVersionerDetectorsHaveNonZeroVersions(t *testing.T) {
	// Loop through all our default detectors and find the ones that
	// implement Versioner. Of those, check each version is not zero.
	// This is required due to an implementation detail of filtering detectors.
	// See: https://github.com/trufflesecurity/trufflehog/blob/v3.63.7/main.go#L624-L638
	for _, detector := range DefaultDetectors() {
		v, ok := detector.(detectors.Versioner)
		if !ok || v.Version() != 0 {
			continue
		}
		t.Errorf(
			"detector %q implements Versioner that returns a zero version",
			detector_typepb.DetectorType_name[int32(detector.Type())],
		)
	}
}

// TestAllDetectorTypesAreInDefaultList ensures every proto-defined DetectorType
// is either present in buildDetectorList() or explicitly excluded below.
//
// If you add a new DetectorType to the proto:
//   - Add its scanner to buildDetectorList() in defaults.go, OR
//   - Add it to excludedFromDefaultList in this test.
func TestAllDetectorTypesAreInDefaultList(t *testing.T) {
	activeTypes := make(map[detector_typepb.DetectorType]struct{})
	for _, d := range DefaultDetectors() {
		activeTypes[d.Type()] = struct{}{}
	}

	for typeInt32, typeName := range detector_typepb.DetectorType_name {
		dt := detector_typepb.DetectorType(typeInt32)
		if _, ok := activeTypes[dt]; ok {
			continue
		}
		if _, ok := excludedFromDefaultList[dt]; ok {
			continue
		}
		t.Errorf(
			"DetectorType %q (value %d) is missing from buildDetectorList(); "+
				"add it to defaults.go or to excludedFromDefaultList in this test",
			typeName, typeInt32,
		)
	}

	// Reverse check: no excluded type should appear in the active list.
	// This catches types that were added to the exclude list by mistake.
	for dt := range excludedFromDefaultList {
		if _, ok := activeTypes[dt]; ok {
			t.Errorf(
				"DetectorType %q is in excludedFromDefaultList but is also present in buildDetectorList(); "+
					"remove it from excludedFromDefaultList",
				detector_typepb.DetectorType_name[int32(dt)],
			)
		}
	}
}

// excludedFromDefaultList contains detector types that are intentionally absent
// from buildDetectorList(). Keep entries grouped and sorted.
//
// TODO: audit this list periodically — entries in the "mistakenly missed" group
// should be removed once the corresponding detector is added to defaults.go.
//nolint:staticcheck // SA1019: intentionally references deprecated DetectorType values to keep them excluded.
var excludedFromDefaultList = map[detector_typepb.DetectorType]struct{}{
	// TODO: these detectors have implementations but were mistakenly never added
	// to buildDetectorList() — discovered by TestAllDetectorTypesAreInDefaultList.
	// They are not added immediately out of caution for the impact on customers/users.
	// Remove each entry once its detector has been carefully added.
	detector_typepb.DetectorType_DatadogApikey: {},
	detector_typepb.DetectorType_Guru:          {},
	detector_typepb.DetectorType_IPInfo:        {},
	detector_typepb.DetectorType_Lob:           {},
	detector_typepb.DetectorType_Rev:           {},
	detector_typepb.DetectorType_TLy:           {},
	detector_typepb.DetectorType_Tru:           {},
	detector_typepb.DetectorType_User:          {},
	detector_typepb.DetectorType_Wit:           {},

	// Reserved / special types.
	detector_typepb.DetectorType_CustomRegex: {}, // added dynamically via engine config, not via buildDetectorList()
	detector_typepb.DetectorType_Test:        {},

	// Deprecated — the proto field is marked deprecated=true and the service
	// no longer exists or has been superseded by a different type.
	detector_typepb.DetectorType_AirtableApiKey:      {},
	detector_typepb.DetectorType_ApiScience:          {},
	detector_typepb.DetectorType_Blablabus:           {},
	detector_typepb.DetectorType_CoinbaseWaaS:        {},
	detector_typepb.DetectorType_CoinMarketCap:       {},
	detector_typepb.DetectorType_CrossBrowserTesting: {},
	detector_typepb.DetectorType_DataFire:            {},
	detector_typepb.DetectorType_EtsyApiKey:          {},
	detector_typepb.DetectorType_FakeJSON:            {},
	detector_typepb.DetectorType_Flowdash:            {},
	detector_typepb.DetectorType_Flowdock:            {},
	detector_typepb.DetectorType_Fusebill:            {},
	detector_typepb.DetectorType_GlitterlyAPI:        {},
	detector_typepb.DetectorType_GoogleApiKey:        {},
	detector_typepb.DetectorType_Happi:               {},
	detector_typepb.DetectorType_Heatmapapi:          {},
	detector_typepb.DetectorType_Integromat:          {},
	detector_typepb.DetectorType_Ipify:               {},
	detector_typepb.DetectorType_Lastfm:              {},
	detector_typepb.DetectorType_Macaddress:          {},
	detector_typepb.DetectorType_Nitro:               {},
	detector_typepb.DetectorType_Nytimes:             {},
	detector_typepb.DetectorType_OnWaterIO:           {},
	detector_typepb.DetectorType_Opengraphr:          {},
	detector_typepb.DetectorType_Passbase:            {},
	detector_typepb.DetectorType_ProspectIO:          {},
	detector_typepb.DetectorType_QuickMetrics:        {},
	detector_typepb.DetectorType_Restpack:            {},
	detector_typepb.DetectorType_Rockset:             {},
	detector_typepb.DetectorType_ScraperSite:         {},
	detector_typepb.DetectorType_Sentiment:           {},
	detector_typepb.DetectorType_SportRadar:          {},
	detector_typepb.DetectorType_Squareup:            {},
	detector_typepb.DetectorType_Text2Data:           {},

	// Intentionally commented out in buildDetectorList() — implementation
	// exists but the detector is disabled (API issues, false positives, etc.).
	detector_typepb.DetectorType_Abstract:         {},
	detector_typepb.DetectorType_AdobeIO:          {},
	detector_typepb.DetectorType_Alconost:         {},
	detector_typepb.DetectorType_Apollo:           {},
	detector_typepb.DetectorType_AzureFunctionKey: {},
	detector_typepb.DetectorType_Besnappy:         {},
	detector_typepb.DetectorType_BlockNative:      {},
	detector_typepb.DetectorType_DailyCO:          {},
	detector_typepb.DetectorType_Debounce:         {},
	detector_typepb.DetectorType_Generic:          {},
	detector_typepb.DetectorType_GetEmail:         {},
	detector_typepb.DetectorType_GetEmails:        {},
	detector_typepb.DetectorType_Hive:             {},
	detector_typepb.DetectorType_IbmCloudUserKey:  {},
	detector_typepb.DetectorType_LineMessaging:    {},
	detector_typepb.DetectorType_M3o:              {},
	detector_typepb.DetectorType_Magnetic:         {},
	detector_typepb.DetectorType_Manifest:         {},
	detector_typepb.DetectorType_Mixpanel:         {},
	detector_typepb.DetectorType_NasdaqDataLink:   {},
	detector_typepb.DetectorType_Raven:            {},
	detector_typepb.DetectorType_Sparkpost:        {},
	detector_typepb.DetectorType_SpotifyKey:       {},
	detector_typepb.DetectorType_TogglTrack:       {},
	detector_typepb.DetectorType_WePay:            {},
	detector_typepb.DetectorType_ZapierWebhook:    {},

	// Not yet implemented — proto enum entry exists but no detector has been
	// written for this service yet.
	detector_typepb.DetectorType_Aerisweather:                            {},
	detector_typepb.DetectorType_Aftership:                               {},
	detector_typepb.DetectorType_Convert:                                 {},
	detector_typepb.DetectorType_Honey:                                   {},
	detector_typepb.DetectorType_HubSpot:                                 {},
	detector_typepb.DetectorType_Paymo:                                   {},
	detector_typepb.DetectorType_Sellfy:                                  {},
	detector_typepb.DetectorType_AirtableMetadataApiKey:                  {},
	detector_typepb.DetectorType_AkamaiToken:                             {},
	detector_typepb.DetectorType_Alphavantage:                            {},
	detector_typepb.DetectorType_AmazonMWS:                               {},
	detector_typepb.DetectorType_AMQP:                                    {},
	detector_typepb.DetectorType_Api2Convert:                             {},
	detector_typepb.DetectorType_Authorize:                               {},
	detector_typepb.DetectorType_Avalara:                                 {},
	detector_typepb.DetectorType_BaseApiIO:                               {},
	detector_typepb.DetectorType_BasisTheory:                             {},
	detector_typepb.DetectorType_BitGo:                                   {},
	detector_typepb.DetectorType_Bored:                                   {},
	detector_typepb.DetectorType_Brightlocal:                             {},
	detector_typepb.DetectorType_Bubble:                                  {},
	detector_typepb.DetectorType_Checkmarket:                             {},
	detector_typepb.DetectorType_CircleCI:                                {},
	detector_typepb.DetectorType_Cloudant:                                {},
	detector_typepb.DetectorType_CloudsightKey:                           {},
	detector_typepb.DetectorType_Cloudways:                               {},
	detector_typepb.DetectorType_CoinGecko:                               {},
	detector_typepb.DetectorType_Cometchat:                               {},
	detector_typepb.DetectorType_ContentfulDelivery:                      {},
	detector_typepb.DetectorType_ContentStack:                            {},
	detector_typepb.DetectorType_Copyscape:                               {},
	detector_typepb.DetectorType_Createsend:                              {},
	detector_typepb.DetectorType_Cricket:                                 {},
	detector_typepb.DetectorType_DigitalOceanSpaces:                      {},
	detector_typepb.DetectorType_Distribusion:                            {}, //nolint:misspell // proto enum name is intentionally spelled this way
	detector_typepb.DetectorType_Duda:                                    {},
	detector_typepb.DetectorType_Duffel:                                  {},
	detector_typepb.DetectorType_Dynadot:                                 {},
	detector_typepb.DetectorType_Dynatrace:                               {},
	detector_typepb.DetectorType_Edusign:                                 {},
	detector_typepb.DetectorType_ElasticPath:                             {},
	detector_typepb.DetectorType_Emailoctopus:                            {},
	detector_typepb.DetectorType_EquinixOauth:                            {},
	detector_typepb.DetectorType_Eversign:                                {},
	detector_typepb.DetectorType_Fastspring:                              {},
	detector_typepb.DetectorType_Feedly:                                  {},
	detector_typepb.DetectorType_Filestack:                               {},
	detector_typepb.DetectorType_Firebase:                                {},
	detector_typepb.DetectorType_FirebaseCloudMessaging:                  {},
	detector_typepb.DetectorType_FlagsmithEnvironmentKey:                 {},
	detector_typepb.DetectorType_FlagsmithToken:                          {},
	detector_typepb.DetectorType_Formstack:                               {},
	detector_typepb.DetectorType_Fountain:                                {},
	detector_typepb.DetectorType_FullContact:                             {},
	detector_typepb.DetectorType_GitHubOld:                               {},
	detector_typepb.DetectorType_Goshippo:                                {},
	detector_typepb.DetectorType_Gosquared:                               {},
	detector_typepb.DetectorType_Hotwire:                                 {},
	detector_typepb.DetectorType_HubSpotOauth:                            {},
	detector_typepb.DetectorType_HypeAuditor:                             {},
	detector_typepb.DetectorType_Image4:                                  {},
	detector_typepb.DetectorType_ImageToText:                             {},
	detector_typepb.DetectorType_Imgix:                                   {},
	detector_typepb.DetectorType_Imgur:                                   {},
	detector_typepb.DetectorType_Infobip:                                 {},
	detector_typepb.DetectorType_JSONbin:                                 {},
	detector_typepb.DetectorType_Jumpseller:                              {},
	detector_typepb.DetectorType_Kairos:                                  {},
	detector_typepb.DetectorType_KakaoTalk:                               {},
	detector_typepb.DetectorType_Kaleyra:                                 {},
	detector_typepb.DetectorType_KalturaAppToken:                         {},
	detector_typepb.DetectorType_KalturaSession:                          {},
	detector_typepb.DetectorType_Keygen:                                  {},
	detector_typepb.DetectorType_KiteConnect:                             {},
	detector_typepb.DetectorType_KubeConfig:                              {},
	detector_typepb.DetectorType_LinkedIn:                                {},
	detector_typepb.DetectorType_Linode:                                  {},
	detector_typepb.DetectorType_Messari:                                 {},
	detector_typepb.DetectorType_Midise:                                  {},
	detector_typepb.DetectorType_Mixcloud:                                {},
	detector_typepb.DetectorType_Mojohelpdesk:                            {},
	detector_typepb.DetectorType_MollieAccessToken:                       {},
	detector_typepb.DetectorType_MollieAPIKey:                            {},
	detector_typepb.DetectorType_Myexperiment:                            {},
	detector_typepb.DetectorType_NetCore:                                 {},
	detector_typepb.DetectorType_NiceHash:                                {},
	detector_typepb.DetectorType_Nordigen:                                {},
	detector_typepb.DetectorType_Nubela:                                  {},
	detector_typepb.DetectorType_OcrSpace:                                {},
	detector_typepb.DetectorType_Onbuka:                                  {},
	detector_typepb.DetectorType_Opendatasoft:                            {},
	detector_typepb.DetectorType_Optidash:                                {},
	detector_typepb.DetectorType_Paddle:                                  {},
	detector_typepb.DetectorType_Page2Images:                             {},
	detector_typepb.DetectorType_Papyrs:                                  {},
	detector_typepb.DetectorType_PDFmyURL:                                {},
	detector_typepb.DetectorType_PendoIntegrationKey:                     {},
	detector_typepb.DetectorType_PlaidToken:                              {},
	detector_typepb.DetectorType_Printfection:                            {},
	detector_typepb.DetectorType_Processst:                               {},
	detector_typepb.DetectorType_Quickbase:                               {},
	detector_typepb.DetectorType_ReCAPTCHA:                               {},
	detector_typepb.DetectorType_Redbooth:                                {},
	detector_typepb.DetectorType_Riotgames:                               {},
	detector_typepb.DetectorType_Rosette:                                 {},
	detector_typepb.DetectorType_Samsara:                                 {},
	detector_typepb.DetectorType_ScrapingDog:                             {},
	detector_typepb.DetectorType_Sendoso:                                 {},
	detector_typepb.DetectorType_ShopeeOpenPlatform:                      {},
	detector_typepb.DetectorType_Simplybook:                              {},
	detector_typepb.DetectorType_SMSApi:                                  {},
	detector_typepb.DetectorType_StreamChatMessaging:                     {},
	detector_typepb.DetectorType_Supportbee:                              {},
	detector_typepb.DetectorType_Surge:                                   {},
	detector_typepb.DetectorType_Teamup:                                  {},
	detector_typepb.DetectorType_TeamViewer:                              {},
	detector_typepb.DetectorType_Telesign:                                {},
	detector_typepb.DetectorType_TencentCloudKey:                         {},
	detector_typepb.DetectorType_Timekit:                                 {},
	detector_typepb.DetectorType_Trimble:                                 {},
	detector_typepb.DetectorType_TwitterApiSecret:                        {},
	detector_typepb.DetectorType_UberServerToken:                         {},
	detector_typepb.DetectorType_Uproc:                                   {},
	detector_typepb.DetectorType_Veevavault:                              {},
	detector_typepb.DetectorType_Vonage:                                  {},
	detector_typepb.DetectorType_Wakatime:                                {},
	detector_typepb.DetectorType_Webengage:                               {},
	detector_typepb.DetectorType_WeChatAppKey:                            {},
	detector_typepb.DetectorType_Woopra:                                  {},
	detector_typepb.DetectorType_WordsApi:                                {},
	detector_typepb.DetectorType_Workday:                                 {},
	detector_typepb.DetectorType_WpEngine:                                {},
	detector_typepb.DetectorType_Yext:                                    {},
	detector_typepb.DetectorType_AzureActiveDirectoryApplicationSecret:   {},
	detector_typepb.DetectorType_AzureCacheForRedisAccessKey:             {},
	detector_typepb.DetectorType_AzureManagementCertificate:              {},
	detector_typepb.DetectorType_AzureMLWebServiceClassicIdentifiableKey: {},
	detector_typepb.DetectorType_AzureSQL:                                {},
	detector_typepb.DetectorType_BuiltWith:                               {},
}

package nigerianfintech

import (
    "context"
    "regexp"

    "github.com/trufflesecurity/trufflehog/v3/pkg/common"
    "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
    "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type scanner struct{}

// Ensure the detector satisfies the interface at compile time.
var _ detectors.Detector = (*scanner)(nil)

func (s scanner) ID() int { return 987 }

func (s scanner) Type() detectorspb.DetectorType {
    return detectorspb.DetectorType_CustomRegex
}

func (s scanner) Description() string {
    return "Detects exposed Nigerian fintech & betting credentials (Paystack, Flutterwave, Remita, Interswitch, SportyBet/BetKing)"
}

// Keywords are used for pre-filtering.
func (s scanner) Keywords() []string {
    return []string{
        "paystack", "flutterwave", "remita", "interswitch", "sportybet", "betking",
        "sk_live", "sk_test", "FLWSECK", "macKey",
    }
}

// FromData will be called when keywords are matched.
func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
    dataStr := string(data)

    patterns := map[string]string{
        "Paystack Secret Key":     `sk_(live|test)_[0-9a-zA-Z]{50,}`,
        "Flutterwave Secret Key":  `FLWSECK[_-]?[a-zA-Z0-9]{30,}`,
        "Flutterwave Test Key":    `FLWSECK_TEST-[a-z0-9]{30,}`,
        "Remita Merchant+Hash":    `[0-9]{10,15}\|?[0-9a-zA-Z]{40,}`,
        "Interswitch MAC Key":     `macKey["']?\s*[:=]\s*["']?[0-9A-Fa-f]{64}`,
        "Betting Admin Token":     `eyJ[A-Za-z0-9-_]{100,}|Bearer [A-Za-z0-9-_]{50,}\.[A-Za-z0-9-_]{50,}\.[A-Za-z0-9-_]{50,}`,
    }

    for name, regexStr := range patterns {
        rx := regexp.MustCompile(regexStr)
        matches := rx.FindAllString(dataStr, -1)

        for _, match := range matches {
            result := detectors.Result{
                DetectorType: detectorspb.DetectorType_CustomRegex,
                Verified:     false, // we can't verify without API call
                ExtraData: map[string]string{
                    "service": name,
                },
            }
            result.Raw = []byte(match)

            if verify {
                // Skip verification for now (too many services)
                result.Verified = false
            }
            results = append(results, result)
        }
    }

    return results, nil
}

// New returns a new detector instance.
func New() detectors.Detector {
    return &scanner{}
}

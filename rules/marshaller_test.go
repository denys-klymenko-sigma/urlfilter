package rules

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRuleMarshall(t *testing.T) {
	faker := gofakeit.New(123)

	for i := 0; i < 1000; i++ {
		newRule := &NetworkRule{}
		require.NoError(t, faker.Struct(newRule))

		// Ensure the rule has a valid pattern to avoid "too wide" errors
		if newRule.pattern == "" || len(newRule.pattern) < 3 {
			newRule.pattern = "||example.org^"
		}

		// Add domain restriction to prevent "too wide" error if needed
		if len(newRule.permittedDomains) == 0 &&
			len(newRule.restrictedDomains) == 0 &&
			newRule.permittedClients == nil &&
			newRule.restrictedClients == nil &&
			len(newRule.permittedClientTags) == 0 &&
			len(newRule.restrictedClientTags) == 0 {
			newRule.permittedDomains = []string{"example.com"}
		}

		// Replace potentially invalid DNSRewrite with a valid one
		// Based on iteration to test different types
		if newRule.DNSRewrite != nil {
			switch i % 5 {
			case 0:
				// No DNSRewrite
				newRule.DNSRewrite = nil
			case 1:
				// CNAME rewrite
				newRule.DNSRewrite = &DNSRewrite{
					NewCNAME: "example.net",
				}
			case 2:
				// A record rewrite
				ip, _ := netip.ParseAddr("192.168.1.1")
				newRule.DNSRewrite = &DNSRewrite{
					NewCNAME: "",
					RCode:    dns.RcodeSuccess,
					RRType:   dns.TypeA,
					Value:    ip,
				}
			case 3:
				// NXDOMAIN rewrite
				newRule.DNSRewrite = &DNSRewrite{
					NewCNAME: "",
					RCode:    dns.RcodeNameError,
				}
			case 4:
				// TXT record rewrite
				newRule.DNSRewrite = &DNSRewrite{
					NewCNAME: "",
					RCode:    dns.RcodeSuccess,
					RRType:   dns.TypeTXT,
					Value:    "text-record-value",
				}
			}
		}

		newRule.denyAllowDomains = append(newRule.denyAllowDomains, "example.org")

		marshalled := newRule.Marshall()
		rule, err := NewNetworkRule(marshalled, 1)
		require.NoError(t, err)

		nullify(rule)
		nullify(newRule)

		marshalledRule, err := json.MarshalIndent(rule, "", "  ")
		require.NoError(t, err)

		actual, err := json.MarshalIndent(newRule, "", "  ")
		require.NoError(t, err)

		require.Equal(t, string(actual), string(marshalledRule))
	}
}

func nullify(rule *NetworkRule) {
	rule.RuleText = ""
	rule.Shortcut = ""
	rule.FilterListID = 1
}

func TestFullFileMarshal(t *testing.T) {
	urls := []string{
		"https://filters.adtidy.org/dns/filter_1.txt",
		"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
	}

	for _, url := range urls {
		t.Run(url, func(t *testing.T) {
			t.Parallel()
			res, err := http.Get(url)
			require.NoError(t, err)
			defer res.Body.Close()

			scanner := bufio.NewScanner(res.Body)

			for scanner.Scan() {
				require.NoError(t, scanner.Err())

				line := scanner.Text()
				if strings.HasPrefix(line, "!") || strings.TrimSpace(line) == "" {
					continue
				}

				rule, err := NewNetworkRule(line, 1)
				require.NoError(t, err)

				ruleText := rule.Marshall()
				require.Equal(t, line, ruleText)
			}
		})
	}
}

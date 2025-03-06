package rules

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

func (rule *NetworkRule) Marshall() string {
	var options []string
	var pattern string

	// Set the pattern, handling the whitelist prefix
	if rule.Whitelist {
		pattern = maskWhiteList
	}

	// Add the pattern
	pattern += rule.pattern

	// Process enabled options
	if rule.enabledOptions != 0 {
		// Handle all possible options
		if rule.IsOptionEnabled(OptionThirdParty) {
			options = append(options, "third-party")
		}
		if rule.IsOptionEnabled(OptionMatchCase) {
			options = append(options, "match-case")
		}
		if rule.IsOptionEnabled(OptionImportant) {
			options = append(options, "important")
		}
		if rule.IsOptionEnabled(OptionBadfilter) {
			options = append(options, "badfilter")
		}
		if rule.IsOptionEnabled(OptionElemhide) {
			options = append(options, "elemhide")
		}
		if rule.IsOptionEnabled(OptionGenerichide) {
			options = append(options, "generichide")
		}
		if rule.IsOptionEnabled(OptionGenericblock) {
			options = append(options, "genericblock")
		}
		if rule.IsOptionEnabled(OptionJsinject) {
			options = append(options, "jsinject")
		}
		if rule.IsOptionEnabled(OptionUrlblock) {
			options = append(options, "urlblock")
		}
		if rule.IsOptionEnabled(OptionContent) {
			options = append(options, "content")
		}
		if rule.IsOptionEnabled(OptionExtension) {
			options = append(options, "extension")
		}
		if rule.IsOptionEnabled(OptionStealth) {
			options = append(options, "stealth")
		}
		if rule.IsOptionEnabled(OptionEmpty) {
			options = append(options, "empty")
		}
		if rule.IsOptionEnabled(OptionMp4) {
			options = append(options, "mp4")
		}
		if rule.IsOptionEnabled(OptionPopup) {
			options = append(options, "popup")
		}
	}

	// Process disabled options
	if rule.disabledOptions != 0 {
		if rule.IsOptionDisabled(OptionThirdParty) {
			options = append(options, "~third-party")
		}
		if rule.IsOptionDisabled(OptionMatchCase) {
			options = append(options, "~match-case")
		}
		if rule.IsOptionDisabled(OptionExtension) {
			options = append(options, "~extension")
		}
	}

	// Process permitted request types
	if rule.permittedRequestTypes != 0 {
		if (rule.permittedRequestTypes & TypeScript) != 0 {
			options = append(options, "script")
		}
		if (rule.permittedRequestTypes & TypeStylesheet) != 0 {
			options = append(options, "stylesheet")
		}
		if (rule.permittedRequestTypes & TypeSubdocument) != 0 {
			options = append(options, "subdocument")
		}
		if (rule.permittedRequestTypes & TypeObject) != 0 {
			options = append(options, "object")
		}
		if (rule.permittedRequestTypes & TypeImage) != 0 {
			options = append(options, "image")
		}
		if (rule.permittedRequestTypes & TypeXmlhttprequest) != 0 {
			options = append(options, "xmlhttprequest")
		}
		if (rule.permittedRequestTypes & TypeMedia) != 0 {
			options = append(options, "media")
		}
		if (rule.permittedRequestTypes & TypeFont) != 0 {
			options = append(options, "font")
		}
		if (rule.permittedRequestTypes & TypeWebsocket) != 0 {
			options = append(options, "websocket")
		}
		if (rule.permittedRequestTypes & TypePing) != 0 {
			options = append(options, "ping")
		}
		if (rule.permittedRequestTypes & TypeOther) != 0 {
			options = append(options, "other")
		}
	}

	// Process restricted request types
	if rule.restrictedRequestTypes != 0 {
		if (rule.restrictedRequestTypes & TypeScript) != 0 {
			options = append(options, "~script")
		}
		if (rule.restrictedRequestTypes & TypeStylesheet) != 0 {
			options = append(options, "~stylesheet")
		}
		if (rule.restrictedRequestTypes & TypeSubdocument) != 0 {
			options = append(options, "~subdocument")
		}
		if (rule.restrictedRequestTypes & TypeObject) != 0 {
			options = append(options, "~object")
		}
		if (rule.restrictedRequestTypes & TypeImage) != 0 {
			options = append(options, "~image")
		}
		if (rule.restrictedRequestTypes & TypeXmlhttprequest) != 0 {
			options = append(options, "~xmlhttprequest")
		}
		if (rule.restrictedRequestTypes & TypeMedia) != 0 {
			options = append(options, "~media")
		}
		if (rule.restrictedRequestTypes & TypeFont) != 0 {
			options = append(options, "~font")
		}
		if (rule.restrictedRequestTypes & TypeWebsocket) != 0 {
			options = append(options, "~websocket")
		}
		if (rule.restrictedRequestTypes & TypePing) != 0 {
			options = append(options, "~ping")
		}
		if (rule.restrictedRequestTypes & TypeOther) != 0 {
			options = append(options, "~other")
		}
	}

	// Process domains
	if len(rule.permittedDomains) > 0 || len(rule.restrictedDomains) > 0 {
		var domains []string

		// Add permitted domains
		domains = append(domains, rule.permittedDomains...)

		// Add restricted domains
		for _, domain := range rule.restrictedDomains {
			domains = append(domains, "~"+domain)
		}

		options = append(options, "domain="+strings.Join(domains, "|"))
	}

	// Process denyallow domains
	if len(rule.denyAllowDomains) > 0 {
		options = append(options, "denyallow="+strings.Join(rule.denyAllowDomains, "|"))
	}

	// Process client tags
	if len(rule.permittedClientTags) > 0 || len(rule.restrictedClientTags) > 0 {
		var tags []string

		// Add permitted tags
		tags = append(tags, rule.permittedClientTags...)

		// Add restricted tags
		for _, tag := range rule.restrictedClientTags {
			tags = append(tags, "~"+tag)
		}

		options = append(options, "ctag="+strings.Join(tags, "|"))
	}

	// Process clients
	if rule.permittedClients != nil && rule.permittedClients.Len() > 0 ||
		rule.restrictedClients != nil && rule.restrictedClients.Len() > 0 {
		var clients []string

		// Add permitted clients
		if rule.permittedClients != nil {
			// Handle IP addresses/prefixes
			for _, n := range rule.permittedClients.nets {
				clients = append(clients, n.String())
			}

			// Handle hostnames
			for _, host := range rule.permittedClients.hosts {
				// Quote client names with special characters
				if strings.ContainsAny(host, " ,|") {
					clients = append(clients, "\""+strings.ReplaceAll(host, "\"", "\\\"")+`"`)
				} else {
					clients = append(clients, host)
				}
			}
		}

		// Add restricted clients
		if rule.restrictedClients != nil {
			prefix := "~"

			// Handle IP addresses/prefixes
			for _, n := range rule.restrictedClients.nets {
				clients = append(clients, prefix+n.String())
			}

			// Handle hostnames
			for _, host := range rule.restrictedClients.hosts {
				// Quote client names with special characters
				if strings.ContainsAny(host, " ,|") {
					clients = append(clients, prefix+`"`+strings.ReplaceAll(host, "\"", "\\\"")+`"`)
				} else {
					clients = append(clients, prefix+host)
				}
			}
		}

		options = append(options, "client="+strings.Join(clients, "|"))
	}

	// Process DNS types
	if len(rule.permittedDNSTypes) > 0 || len(rule.restrictedDNSTypes) > 0 {
		var types []string

		// Add permitted DNS types
		for _, dnsType := range rule.permittedDNSTypes {
			types = append(types, dns.TypeToString[dnsType])
		}

		// Add restricted DNS types
		for _, dnsType := range rule.restrictedDNSTypes {
			types = append(types, "~"+dns.TypeToString[dnsType])
		}

		options = append(options, "dnstype="+strings.Join(types, "|"))
	}

	// Add DNS rewrite if present
	if rule.DNSRewrite != nil {
		options = handleDNSrewrite(rule, options)
	}

	// Combine all options and pattern into the final rule
	if len(options) > 0 {
		return pattern + "$" + strings.Join(options, ",")
	}

	return pattern
}

func handleDNSrewrite(rule *NetworkRule, options []string) []string {
	// Format based on the expected loadDNSRewrite function format

	// Case 1: CNAME rewrite - use shorthand format
	if rule.DNSRewrite.NewCNAME != "" {
		return append(options, "dnsrewrite="+rule.DNSRewrite.NewCNAME)

	}

	// Case 2: Special RCode values - use shorthand uppercase format
	if rule.DNSRewrite.RCode != dns.RcodeSuccess {
		var value string
		switch rule.DNSRewrite.RCode {
		case dns.RcodeNameError:
			value = "NXDOMAIN"
		case dns.RcodeRefused:
			value = "REFUSED"
		case dns.RcodeServerFailure:
			value = "SERVFAIL"
		case dns.RcodeFormatError:
			value = "FORMERR"
		case dns.RcodeSuccess:
			value = "NOERROR"
		default:
			// Skip unknown RCodes to avoid "unknown keyword" errors
			return options
		}
		return append(options, "dnsrewrite="+value)
	}
	// Case 3: IP addresses - use shorthand format for supported types
	if rule.DNSRewrite.RRType == dns.TypeA || rule.DNSRewrite.RRType == dns.TypeAAAA {
		if ip, ok := rule.DNSRewrite.Value.(netip.Addr); ok {
			options = append(options, "dnsrewrite="+ip.String())
		}
		return options
	}
	// Case 4: Other record types - use normal format with semicolons (NOERROR;TYPE;VALUE)
	if rule.DNSRewrite.RRType != 0 {
		// Skip if record type string doesn't exist
		rrTypeStr, exists := dns.TypeToString[rule.DNSRewrite.RRType]
		if !exists {
			return options
		}

		rcodeStr := "NOERROR" // Default for RcodeSuccess
		var valStr string

		switch rule.DNSRewrite.RRType {
		case dns.TypeCNAME, dns.TypePTR, dns.TypeTXT:
			// For string values
			if strVal, ok := rule.DNSRewrite.Value.(string); ok {
				valStr = strVal
			}

		case dns.TypeMX:
			// For MX records
			if mx, ok := rule.DNSRewrite.Value.(*DNSMX); ok {
				valStr = fmt.Sprintf("%d %s", mx.Preference, mx.Exchange)
			}

		case dns.TypeSRV:
			// For SRV records
			if srv, ok := rule.DNSRewrite.Value.(*DNSSRV); ok {
				valStr = fmt.Sprintf("%d %d %d %s",
					srv.Priority,
					srv.Weight,
					srv.Port,
					srv.Target)
			}

		case dns.TypeHTTPS, dns.TypeSVCB:
			// For HTTPS/SVCB records
			if svcb, ok := rule.DNSRewrite.Value.(*DNSSVCB); ok {
				valStr = fmt.Sprintf("%d %s", svcb.Priority, svcb.Target)
				// Add parameters if any
				if len(svcb.Params) > 0 {
					// Reconstruct parameters
					for k, v := range svcb.Params {
						valStr += fmt.Sprintf(" %s=%s", k, v)
					}
				}
			}
		}

		if valStr != "" {
			options = append(options, "dnsrewrite="+rcodeStr+";"+rrTypeStr+";"+valStr)
		}
	}
	return options
}

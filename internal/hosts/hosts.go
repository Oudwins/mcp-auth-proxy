package hosts

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

type Rule struct {
	Scheme   string // "http" or "https"
	Host     string // lowercase; IPv6 literals keep their brackets in canonical form
	Port     string
	Wildcard bool
}

var (
	entryPattern = regexp.MustCompile(`^(?:(https?)://)?(\*\.)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::(\d{1,5}))?$`)
	defaultPorts = map[string]string{"http": "80", "https": "443"}
)

func ParseRule(entry string) (Rule, error) {
	match := entryPattern.FindStringSubmatch(strings.TrimSpace(entry))
	if match == nil {
		return Rule{}, fmt.Errorf("%q is not a valid host entry (expected [http(s)://]host[:port] or *.domain)", entry)
	}
	scheme := match[1]
	if scheme == "" {
		scheme = "https"
	}
	wildcard := match[2] != ""
	host := strings.ToLower(match[3])
	if wildcard && !strings.Contains(host, ".") {
		return Rule{}, fmt.Errorf("%q is too broad, wildcards need a domain like *.example.com", entry)
	}
	if wildcard && strings.HasPrefix(host, "[") {
		return Rule{}, fmt.Errorf("%q cannot combine a wildcard with an IP address", entry)
	}
	if strings.HasPrefix(host, "[") {
		addr, err := netip.ParseAddr(host[1 : len(host)-1])
		if err != nil {
			return Rule{}, fmt.Errorf("%q is not a valid IPv6 address", entry)
		}
		host = "[" + addr.String() + "]"
	}
	port := match[4]
	if port == "" {
		port = defaultPorts[scheme]
	}
	return Rule{Scheme: scheme, Host: host, Port: port, Wildcard: wildcard}, nil
}

func Compile(entries []string) ([]Rule, error) {
	rules := make([]Rule, 0, len(entries))
	for _, entry := range entries {
		rule, err := ParseRule(entry)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Allowed matches on the hostname string only, no DNS.
func Allowed(rules []Rule, target *url.URL) bool {
	scheme := strings.ToLower(target.Scheme)
	port := target.Port()
	if port == "" {
		port = defaultPorts[scheme]
	}
	host := strings.ToLower(target.Hostname())
	if strings.Contains(host, ":") {
		if addr, err := netip.ParseAddr(host); err == nil {
			host = "[" + addr.String() + "]"
		} else {
			host = "[" + host + "]"
		}
	}
	for _, rule := range rules {
		if rule.Scheme != scheme || rule.Port != port {
			continue
		}
		if rule.Wildcard {
			if strings.HasSuffix(host, "."+rule.Host) {
				return true
			}
		} else if host == rule.Host {
			return true
		}
	}
	return false
}

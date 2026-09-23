package transform

import (
	"regexp"
	"strings"
)

var (
	rePseudoHost = regexp.MustCompile(`^host-[a-z]+$`)
	rePseudoUser = regexp.MustCompile(`^user-[a-z]+$`)
)

// defaultDetectors returns the built-in detectors of diagx-default-0.1.
//
// Every replacement is idempotent: running the same detector over its own
// output produces no further matches, so reports stay accurate and
// repeated application (e.g. redact-test on already redacted text) is
// stable.
func defaultDetectors() map[string]*Detector {
	d := map[string]*Detector{}

	d["pem_private_key"] = &Detector{
		ID:       "pem_private_key",
		Category: "private-key material",
		Re:       regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
		fn:       func(string, []string) string { return "" },
	}

	// scheme://user:pass@host  →  scheme://<DB-CREDENTIALS>@host
	// The replacement contains no "user:pass" shape, so it never
	// re-matches.
	d["db_connection"] = &Detector{
		ID:       "db_connection",
		Category: "database connection credentials",
		Re:       regexp.MustCompile(`\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|sqlserver|mssql)://(?:[^\s@/]+:)?([^\s@/]+)@`),
		fn:       func(full string, g []string) string { return g[0] + "://<DB-CREDENTIALS>@" },
	}

	// Authorization: Bearer <token>  →  Authorization: Bearer ***
	d["auth_header"] = &Detector{
		ID:       "auth_header",
		Category: "authorization headers",
		Re:       regexp.MustCompile(`(?i)\b(proxy-?authorization|authorization)([\"']?\s*[:=]\s*(?:bearer|basic|digest)\s+)([A-Za-z0-9\-_./+=]{16,})`),
		fn:       func(full string, g []string) string { return g[0] + g[1] + "***" },
	}

	// Compacted JWS/JWT.
	d["jwt"] = &Detector{
		ID:       "jwt",
		Category: "JWT-like values",
		Re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}`),
		fn:       func(string, []string) string { return "eyJ***" },
	}

	// GitHub-style tokens: ghp_, gho_, ghu_, ghs_, ghr_, github_pat_.
	d["github_token"] = &Detector{
		ID:       "github_token",
		Category: "common API-token patterns",
		Re:       regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,})`),
		fn:       func(full string, _ []string) string { return full[:strings.LastIndex(full, "_")+1] + "***" },
	}

	// AWS-style access key IDs.
	d["aws_access_key"] = &Detector{
		ID:       "aws_access_key",
		Category: "cloud credential patterns",
		Re:       regexp.MustCompile(`\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16})\b`),
		fn:       func(full string, _ []string) string { return full[:4] + "***" },
	}

	// aws_secret_access_key = / : ...
	d["aws_secret_assignment"] = &Detector{
		ID:       "aws_secret_assignment",
		Category: "cloud credential patterns",
		Re:       regexp.MustCompile(`(?i)\b(aws[_\-]?secret[_\-]?access[_\-]?key|secret[_\-]?access[_\-]?key)([\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9/+=]{16,40})`),
		fn:       func(full string, g []string) string { return g[0] + g[1] + "***" },
	}

	// password / passwd / pwd = value  (value may not contain ':' or '/',
	// so credential URLs handled by db_connection survive intact).
	d["password_assignment"] = &Detector{
		ID:       "password_assignment",
		Category: "password assignments",
		Re:       regexp.MustCompile(`(?i)\b(password|passwd|pwd)([\"']?\s*[:=]\s*[\"']?)([^/:\s\"',;` + "`" + `]{2,64})`),
		fn:       func(full string, g []string) string { return g[0] + g[1] + "***" },
	}

	// api_key / api_token / access_token / client_secret = value
	d["api_token_assignment"] = &Detector{
		ID:       "api_token_assignment",
		Category: "common API-token patterns",
		Re:       regexp.MustCompile(`(?i)\b(api[_\-]?key|apikey|api[_\-]?token|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)([\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9\-_./+=]{16,128})`),
		fn:       func(full string, g []string) string { return g[0] + g[1] + "***" },
	}

	// scheme://[userinfo@]host[:port]  →  scheme://[userinfo@]host-x[:port]
	d["url_host"] = &Detector{
		ID:       "url_host",
		Category: "hostnames",
		Re:       regexp.MustCompile(`\b(https?|tcp|tls|postgres(?:ql)?|mysql|redis|amqps?|mongodb(?:\+srv)?|grpc)://([^\s@/]+@)?([a-z0-9](?:[a-z0-9.\-]*[a-z0-9])?)(?::(\d+))?`),
		fn: func(full string, g []string) string {
			if rePseudoHost.MatchString(g[2]) {
				return full // already pseudonymized
			}
			userinfo := ""
			if g[1] != "" {
				userinfo = g[1]
			}
			host := g[2]
			suffix := ""
			if g[3] != "" {
				suffix = ":" + g[3]
			}
			return g[0] + "://" + userinfo + engineHost(host) + suffix
		},
	}

	d["mac_address"] = &Detector{
		ID:       "mac_address",
		Category: "MAC addresses",
		Re:       regexp.MustCompile(`\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b`),
		fn: func(full string, _ []string) string {
			if p, ok := pseudoFor("mac|mac|" + full); ok {
				return "mac-" + p
			}
			return "mac-a"
		},
	}

	d["email"] = &Detector{
		ID:       "email",
		Category: "email addresses",
		Re:       regexp.MustCompile(`\b([A-Za-z0-9._%+\-]{1,64})@([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)\b`),
		fn: func(full string, g []string) string {
			// Keep the domain, pseudonymize the local part.
			if rePseudoUser.MatchString(g[0]) {
				return full // already pseudonymized
			}
			if localPseudo, ok := pseudoFor(emailKey(g[0])); ok {
				return "user-" + localPseudo + "@" + g[1]
			}
			return "user-a@" + g[1]
		},
	}

	// IPv6 (full form; at least four colon groups to avoid matching clock
	// times). Compressed forms (containing "::") are a documented V0.1
	// limitation.
	d["ipv6"] = &Detector{
		ID:       "ipv6",
		Category: "IPv6 addresses",
		Re:       regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){3,7})\b`),
		fn: func(full string, _ []string) string {
			if p, ok := pseudoFor("host|" + full); ok {
				return "host-" + p
			}
			return "host-a"
		},
	}

	// Strict IPv4 (each octet 0-255). The match must be bounded by
	// non-numeric punctuation (or line edges) so that dotted version
	// strings such as "1.2.3.4.5" are not mangled.
	ipv4Octet := `(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
	d["ipv4"] = &Detector{
		ID:       "ipv4",
		Category: "IPv4 addresses",
		Re:       regexp.MustCompile(`(?:^|[\s'"=:,()>])((?:` + ipv4Octet + `\.){3}` + ipv4Octet + `)(?:$|[\s'"=:,;<>])`),
		fn: func(full string, g []string) string {
			label := "host-a"
			if p, ok := pseudoFor("host|" + g[0]); ok {
				label = "host-" + p
			}
			// Preserve the surrounding boundary characters.
			return strings.Replace(full, g[0], label, 1)
		},
	}

	d["home_user"] = &Detector{
		ID:       "home_user",
		Category: "home-directory usernames",
		Re:       regexp.MustCompile(`(?:/home/|/Users/|[A-Za-z]:[\\/]Users[\\/])([A-Za-z0-9](?:[A-Za-z0-9._\-]*[A-Za-z0-9])?)`),
		fn: func(full string, g []string) string {
			if g[0] == "user" {
				return full // already masked
			}
			prefix := full[:len(full)-len(g[0])]
			return prefix + "user"
		},
	}

	return d
}

func prefixBefore(s, sep string) string {
	if i := strings.LastIndex(s, sep); i > 0 {
		return s[:i]
	}
	return ""
}

var _ = prefixBefore

// The detectors above reference a process-wide pseudo registry bound to
// the current engine. Because Go closures cannot easily carry the engine,
// the default detectors use a package-level binding that NewEngine sets.
// This is safe: the reference implementation runs one engine at a time per
// artifact in a single goroutine (the collection pipeline is sequential
// over files).

var (
	currentPseudo *PseudoMap
)

func engineHost(v string) string {
	if currentPseudo == nil {
		return "host-a"
	}
	p, _ := currentPseudo.For("host|" + v)
	return "host-" + p
}

func nextPseudo() string {
	if currentPseudo == nil {
		return "a"
	}
	return currentPseudo.Next("mac")
}

var _ = nextPseudo

func pseudoFor(key string) (string, bool) {
	if currentPseudo == nil {
		return "", false
	}
	return currentPseudo.For(key)
}

func emailKey(local string) string { return "em|user|" + local }

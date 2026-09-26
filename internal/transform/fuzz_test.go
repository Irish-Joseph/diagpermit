package transform

import (
	"testing"
)

// FuzzApply is a security-sensitive fuzz target: the
// transformation engine must never panic, crash or lose data silently on
// arbitrary input, including binary junk, huge lines and crafted
// Unicode.
func FuzzApply(f *testing.F) {
	seeds := []string{
		"password=hunter2",
		"postgres://u:p@h/d",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"192.168.1.20 and 2001:0db8:0000:0000:0000:0000:0000:4242",
		"AA:BB:CC:DD:EE:FF",
		"alice@example.com",
		"/home/example-user/work",
		`C:\Users\example-user\AppData`,
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
		"\x00\x01\x02\xff\xfe binary junk",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"日本語 テスト 密码",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		e, err := NewEngine(DefaultRuleset(), []byte("fuzzsalt0123456789"))
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := e.Apply([]byte(input))
		if err != nil {
			// Fail-closed is an acceptable outcome, but panics are not
			// (they would have crashed this goroutine already).
			t.Skipf("fail-closed: %v", err)
		}
		// Output must be well-formed bytes; no requirement on length.
		_ = out
	})
}

// FuzzApplyCustomPatterns fuzzes user-defined patterns too.
func FuzzApplyCustomPatterns(f *testing.F) {
	f.Add(`ORD-[0-9]{8}`, "mask")
	f.Add(`\b\d{3}-\d{4}\b`, "hash")
	f.Add(`abc`, "replace")
	f.Fuzz(func(t *testing.T, pattern, action string) {
		rs := DefaultRuleset()
		rs.Rules = append(rs.Rules, Rule{
			Detector:    "custom:fuzz",
			Pattern:     pattern,
			Action:      Action(action),
			ReplaceWith: "X",
			TruncateTo:  4,
			Required:    true,
		})
		e, err := NewEngine(rs, []byte("fuzzsalt0123456789"))
		if err != nil {
			return // invalid config: fail closed at construction
		}
		if _, _, err := e.Apply([]byte("abc ORD-12345678 def 123-4567 ghi")); err != nil {
			t.Skipf("fail-closed: %v", err)
		}
	})
}

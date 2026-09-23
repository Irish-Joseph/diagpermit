package transform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The synthetic secret corpus (spec section 42). These redaction
// regression tests guarantee that known synthetic patterns are removed,
// that benign content is preserved, and that the transformation report
// never contains original values.

const corpusDir = "../../testdata/secretcorpus"

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	salt := []byte("deadbeefdeadbeefdeadbeefdeadbeef")
	e, err := NewEngine(DefaultRuleset(), salt)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func applyFile(t *testing.T, name string) (string, []DetectorReport) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpusDir, name))
	if err != nil {
		t.Fatal(err)
	}
	out, rep, err := newTestEngine(t).Apply(data)
	if err != nil {
		t.Fatalf("%s: fail-closed: %v", name, err)
	}
	return string(out), rep
}

func containsNone(t *testing.T, out, name string, forbidden ...string) {
	t.Helper()
	for _, f := range forbidden {
		if strings.Contains(out, f) {
			t.Errorf("%s: output still contains secret %q\noutput:\n%s", name, f, out)
		}
	}
}

func containsAll(t *testing.T, out, name string, required ...string) {
	t.Helper()
	for _, r := range required {
		if !strings.Contains(out, r) {
			t.Errorf("%s: output missing expected %q\noutput:\n%s", name, r, out)
		}
	}
}

func TestRedactJWT(t *testing.T) {
	out, _ := applyFile(t, "jwt.log")
	containsNone(t, out, "jwt",
		"dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"eyJzdWIiOiIxMjM0NTY3ODkwIn0")
	containsAll(t, out, "jwt", "eyJ***", "short eyJhYi5jZC5lZi5naC5pai5r end")
}

func TestRedactGitHub(t *testing.T) {
	out, _ := applyFile(t, "github.log")
	containsNone(t, out, "github",
		"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456789",
		"11111111111111111111111111111111111111")
	containsAll(t, out, "github", "ghp_***", "github_pat_***", "gho_***")
}

func TestRedactAWS(t *testing.T) {
	out, _ := applyFile(t, "aws.log")
	containsNone(t, out, "aws",
		"AKIAIOSFODNN7EXAMPLE", "ASIA1234567890ABCDEF",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	containsAll(t, out, "aws", "AKIA***", "ASIA***", "***")
}

func TestRedactDB(t *testing.T) {
	out, _ := applyFile(t, "db.log")
	containsNone(t, out, "db",
		"Sup3rS3cretP4ssw0rd", "hunter22", "abcdef123456",
		"Sup3rS3cret@", "R00tPass", "cachekey")
	containsAll(t, out, "db", "<DB-CREDENTIALS>")
	if c := strings.Count(out, "<DB-CREDENTIALS>"); c != 3 {
		t.Errorf("db: expected 3 <DB-CREDENTIALS>, got %d\n%s", c, out)
	}
}

func TestRedactAuthHeader(t *testing.T) {
	out, _ := applyFile(t, "auth.log")
	containsNone(t, out, "auth",
		"abcdef1234567890abcdef1234567890ABCDEF",
		"dXNlcjpwYXNzd29yZA==")
	containsAll(t, out, "auth", "Bearer ***", "basic ***")
}

func TestRedactPEM(t *testing.T) {
	out, _ := applyFile(t, "pem.log")
	containsNone(t, out, "pem", "BEGIN RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA7v5x")
	containsAll(t, out, "pem", "keep this line visible")
}

func TestRedactConnections(t *testing.T) {
	out, _ := applyFile(t, "connections.log")
	containsNone(t, out, "connections", "MongoPass123", "AmqpPass!")
	containsAll(t, out, "connections", "<DB-CREDENTIALS>")
}

func TestRedactEmails(t *testing.T) {
	out, _ := applyFile(t, "emails.log")
	containsNone(t, out, "emails", "alice.smith", "bob@corp.io", "carol-jones")
	containsAll(t, out, "emails", "@example.com", "@sub.domain.example.org", "not-an-email a@b")
}

func TestRedactIPv4(t *testing.T) {
	out, _ := applyFile(t, "ipv4.log")
	containsNone(t, out, "ipv4", "192.168.1.20", "10.0.0.55")
	containsAll(t, out, "ipv4", "host-a", "host-b",
		"999.999.999.999 ignored", "version 1.2.3.4.5 has five parts")
	// URL host: pseudonymized via url_host, port preserved.
	if !strings.Contains(out, ":8080/x") {
		t.Errorf("ipv4: port should survive URL host pseudonymization:\n%s", out)
	}
}

func TestRedactIPv6(t *testing.T) {
	out, _ := applyFile(t, "ipv6.log")
	containsNone(t, out, "ipv6", "2001:0db8:0000:0000:0000:0000:0000:4242")
	containsAll(t, out, "ipv6", "host-", "clock 01:02:03 is fine")
}

func TestRedactHome(t *testing.T) {
	out, _ := applyFile(t, "home.log")
	containsNone(t, out, "home", "/home/josep", "/Users/josep", "Users\\josep")
	containsAll(t, out, "home", "/home/user/work/app.log", "/Users/user/Library/Logs/app.log", `C:\Users\user\AppData`)
}

func TestRedactMAC(t *testing.T) {
	out, _ := applyFile(t, "mac.log")
	containsNone(t, out, "mac", "AA:BB:CC:DD:EE:FF", "11-22-33-44-55-66")
	containsAll(t, out, "mac", "mac-a", "mac-b")
}

func TestBenignUntouched(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(corpusDir, "benign.log"))
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t)
	out, _, err := e.Apply(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(data) {
		t.Errorf("benign content was modified:\nbefore:\n%s\nafter:\n%s", data, out)
	}
}

// TestReportLeaksNothing guarantees the transformation report never
// contains original secret values (spec section 16).
func TestReportLeaksNothing(t *testing.T) {
	secrets := []string{
		"dozjgNryP4J3jVmNHl0w5N", "AbCdEfGhIjKlMnOpQrSt",
		"AKIAIOSFODNN7EXAMPLE", "Sup3rS3cret", "alice.smith",
		"192.168.1.20", "AA:BB:CC:DD:EE:FF", "josep",
	}
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if ent.IsDir() || ent.Name() == "README.md" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(corpusDir, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		e := newTestEngine(t)
		_, rep, err := e.Apply(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range rep {
			for _, s := range secrets {
				if strings.Contains(d.Category, s) || strings.Contains(d.Detector, s) {
					t.Errorf("%s: report field leaks secret %q", ent.Name(), s)
				}
			}
		}
	}
}

// TestStablePseudonymization guarantees the same value maps to the same
// pseudonym within one artifact (spec section 15).
func TestStablePseudonymization(t *testing.T) {
	content := []byte("a 192.168.1.20 b 192.168.1.20 c 10.0.0.5 d")
	e := newTestEngine(t)
	out, _, err := e.Apply(content)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)
	first := strings.Index(outStr, "host-")
	if first < 0 {
		t.Fatalf("no pseudonym found: %s", outStr)
	}
	// All occurrences of the first IP must share the label.
	firstLabel := outStr[first : first+len("host-a")]
	if !strings.Contains(outStr[first:], firstLabel) {
		t.Fatalf("unexpected: %s", outStr)
	}
	// The different IP must get a different label.
	countA := strings.Count(outStr, firstLabel)
	if countA != 2 {
		t.Errorf("expected 2 occurrences of %s, got %d: %s", firstLabel, countA, outStr)
	}
	if strings.Count(outStr, "host-b") != 1 {
		t.Errorf("expected 1 occurrence of host-b: %s", outStr)
	}
}

// TestFailClosedCustomPattern guarantees an unparseable user pattern
// aborts engine construction (fail closed at configuration time).
func TestFailClosedCustomPattern(t *testing.T) {
	rs := DefaultRuleset()
	rs.Rules = append(rs.Rules, Rule{
		Detector: "custom:broken",
		Pattern:  "([unclosed",
		Action:   ActionMask,
		Required: true,
	})
	if _, err := NewEngine(rs, []byte("salt")); err == nil {
		t.Fatal("expected error for unparseable pattern")
	}
}

// TestCustomDetectorApplied checks user-defined detectors run with the
// configured action.
func TestCustomDetectorApplied(t *testing.T) {
	rs := DefaultRuleset()
	rs.Rules = append(rs.Rules, Rule{
		Detector: "custom:order-id",
		Pattern:  `ORD-[0-9]{8}`,
		Action:   ActionMask,
		Required: true,
	})
	e, err := NewEngine(rs, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := e.Apply([]byte("order ORD-12345678 shipped"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "order *** shipped" {
		t.Errorf("unexpected: %s", out)
	}
}

package consent

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrompterPreservesBufferedAnswers(t *testing.T) {
	var output bytes.Buffer
	p := NewPrompter(strings.NewReader("yes\nno\n"), &output)

	first, err := p.Confirm("first?", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Confirm("second?", true)
	if err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Fatalf("unexpected answers: first=%v second=%v", first, second)
	}
}

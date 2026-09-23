package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// section prints a titled banner like the spec's CLI examples.
func section(w io.Writer, title string) {
	fmt.Fprintf(w, "\n%s\n%s\n", title, strings.Repeat("─", max(16, len(title))))
}

// now/parseTime are indirections to keep the expiry check testable.
var (
	now       = time.Now
	parseTime = time.Parse
)

func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

func readRandom(b []byte) (int, error) { return rand.Read(b) }

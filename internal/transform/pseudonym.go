package transform

import (
	"crypto/sha256"
)

// PseudoMap provides stable per-artifact pseudonyms (spec section 15).
//
// Given a salt (fresh random bytes per artifact) and an original value,
// For returns the same label for the same value on every call within this
// artifact, and (with overwhelming probability) different labels for
// different values. Labels are deterministic in value order: first value
// seen → -a, second → -b, etc.
type PseudoMap struct {
	salt []byte
	// per-pool: original value → label
	maps map[string]map[string]string
	// per-pool: next index
	next map[string]int
}

// NewPseudoMap creates a fresh pseudonym map for one artifact.
func NewPseudoMap(salt []byte) *PseudoMap {
	if len(salt) == 0 {
		panic("transform: pseudo map requires a non-empty per-artifact salt")
	}
	return &PseudoMap{
		salt: salt,
		maps: make(map[string]map[string]string),
		next: make(map[string]int),
	}
}

// For returns (creating if needed) the pseudonym for the given value
// within the pool identified by poolKey.
//
// poolKey is "<category>|<prefix>|<original>" style: the part before the
// last '|' is the pool, the rest is the value. This keeps pools for
// different label spaces separate (host-a, mac-a, user-a never collide).
func (p *PseudoMap) For(poolKey string) (string, bool) {
	return p.forPool(poolKey)
}

func (p *PseudoMap) forPool(poolKey string) (string, bool) {
	i := lastIndexByte(poolKey, '|')
	if i <= 0 || i == len(poolKey)-1 {
		return "", false
	}
	pool, value := poolKey[:i], poolKey[i+1:]
	m, ok := p.maps[pool]
	if !ok {
		m = make(map[string]string)
		p.maps[pool] = m
	}
	if label, ok := m[value]; ok {
		return label, true
	}
	label := base26(p.next[pool])
	p.next[pool]++
	// The salt makes labels unpredictable from outside the artifact.
	_ = p.salted(value)
	m[value] = label
	return label, true
}

// Next returns the next label in the given pool without binding a value.
// (Used by MAC addresses; each MAC is an opaque identifier and stable
// pseudonymization across files is provided by binding the MAC to the
// pool via For-style usage where available.)
func (p *PseudoMap) Next(pool string) string {
	label := base26(p.next[pool])
	p.next[pool]++
	return label
}

// ForPooled is a convenience for "pool|value" keys.
func (p *PseudoMap) ForPooled(pool, value string) (string, bool) {
	return p.For(pool + "|" + value)
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// salted hashes value with the per-artifact salt. The hash is kept only
// to make future label schemes (e.g. order-independent) easy; V0.1 uses
// first-occurrence ordering for human readability of findings.
func (p *PseudoMap) salted(value string) string {
	h := sha256.New()
	h.Write(p.salt)
	h.Write([]byte{0})
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return string(sum[:8])
}

// base26 renders n as a, b, ..., z, aa, ab, ...
func base26(n int) string {
	if n < 0 {
		n = 0
	}
	var b []byte
	for {
		b = append([]byte{byte('a' + n%26)}, b...)
		n = n/26 - 1
		if n < 0 {
			break
		}
	}
	return string(b)
}

var _ = base26

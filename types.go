/*
   Affinity - Private groups as a service
   Copyright (C) 2014  Canonical, Ltd.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Library General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package affinity

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
)

// AnyId is a wildcard match for any valid, authenticated identifier.
const AnyId = "*"

// Principal defines a singular or corporate identity.
type Principal struct {
	Scheme string
	Id     string
}

// Equals tests if two Principal instances are identical.
func (p Principal) Equals(other Principal) bool {
	return p.Scheme == other.Scheme && p.Id == other.Id
}

func (p Principal) Contains(other Principal) bool {
	if p.Wildcard() {
		return p.Scheme == other.Scheme
	}
	return p.Equals(other)
}

// String returns a human-readable, locally-unique URI representation of the identity.
func (p Principal) String() string {
	return fmt.Sprintf("%s:%s", p.Scheme, p.Id)
}

func (p Principal) Wildcard() bool {
	return p.Id == AnyId
}

// ParsePrincipal parses a locally-unique URI representation of an identity into a Principal.
func ParsePrincipal(s string) (p Principal, err error) {
	i := strings.Index(s, ":")
	if i == -1 || i == 0 || i == len(s)-1 {
		return p, fmt.Errorf("parse error: invalid User format: %q", s)
	}
	return Principal{Scheme: s[0:i], Id: s[i+1:]}, nil
}

func MustParsePrincipal(s string) Principal {
	p, err := ParsePrincipal(s)
	if err != nil {
		panic(err)
	}
	return p
}

/*
// Contains tests if the principal is contained by the group, including
// subgroups.
func (g Group) Contains(p Principal) bool {
	// Are we matching a group?
	matchGroup, isMatchGroup := p.(Group)
	// Iteratively recurse through nested groups, avoiding recursion.
	var pending []Principal
	pending = append(pending, g)
	for i := 0; len(pending) > 0; i++ {
		next := pending[0]
		pending = pending[1:]
		if subGroup, isGroup := next.(Group); isGroup {
			// If we're matching a group, test for group id equality
			if isMatchGroup && matchGroup.Equals(subGroup.Identity) {
				return true
			}
			pending = append(pending, subGroup.Members...)
		} else {
			if next.Contains(p) {
				return true
			}
		}
	}
	return false
}
*/

// TokenInfo stores any RFC 2617 authorization token data,
// including custom provider tokens.
type TokenInfo struct {
	Scheme string
	Values url.Values
}

// NewTokenInfo creates a new TokenInfo instance.
func NewTokenInfo(scheme string) *TokenInfo {
	return &TokenInfo{
		Scheme: scheme,
		Values: url.Values{},
	}
}

// Realm gets the standard 'realm' value, as specified in RFC 2617.
func (t *TokenInfo) Realm() string {
	return t.Values.Get("realm")
}

// ParseTokenInfo parses an RFC 2617 format authorization header.
func ParseTokenInfo(header string) (*TokenInfo, error) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed authentication header: %q", header)
	}
	scheme := parts[0]
	paramString := parts[1]

	token := &TokenInfo{Scheme: scheme, Values: url.Values{}}
	parts = strings.Split(paramString, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		kvpair := strings.Split(part, "=")
		if len(kvpair) != 2 {
			return nil, fmt.Errorf("malformed authentication param: %q", part)
		}
		key, value := kvpair[0], kvpair[1]
		value = strings.Trim(value, `"`)
		value = strings.Replace(value, `\"`, `"`, -1)
		token.Values.Add(key, value)
	}
	return token, nil
}

// Serialize renders an RFC 2617-compatible authorization string.
func (t *TokenInfo) Serialize() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s", t.Scheme)
	first := true
	for key, values := range t.Values {
		for _, value := range values {
			if first {
				first = false
			} else {
				fmt.Fprintf(&buf, ",")
			}
			fmt.Fprintf(&buf, " %s=%s", key, value)
		}
	}
	return buf.String()
}

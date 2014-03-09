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
type Principal interface {
	// String returns a string representation of the principal
	String() string
	// SchemeId returns the scheme and distinct identity of the principal
	SchemeId() (string, string)
	// Contains tests if a given user is contained by this one.
	// Functionally, Contains behaves according to the following rules:
	// A User contains itself and only itself.
	// A Group contains a given user if that user is a member, or contained by
	// some member of the group.
	Contains(member Principal) bool
}

// Group defines a corporate principal identity composed of zero or more principal members.
type Group struct {
	Identity
	Members []Principal
}

// User defines a singular, individual principal identity.
type User struct {
	Identity
}

// Identity defines a principal identifier distinct within an authentication scheme.
type Identity struct {
	Scheme, Id string
}

// Equals tests if two Identity instances are identical.
func (id Identity) Equals(other Identity) bool {
	return id.Scheme == other.Scheme && id.Id == other.Id
}

// String returns a human-readable, locally-unique URI representation of the identity.
func (id Identity) String() string {
	return fmt.Sprintf("%s:%s", id.Scheme, id.Id)
}

func (id Identity) SchemeId() (string, string) {
	return id.Scheme, id.Id
}

func (user User) Wildcard() bool {
	return user.Id == AnyId
}

func (user User) Contains(p Principal) bool {
	scheme, id := p.SchemeId()
	if user.Wildcard() {
		return user.Scheme == scheme
	}
	return user.Scheme == scheme && user.Id == id
}

// ParseUser parses a locally-unique URI representation of an identity into a User.
func ParseUser(s string) (u User, err error) {
	i := strings.Index(s, ":")
	if i == -1 || i == 0 || i == len(s)-1 {
		return u, fmt.Errorf("Parse error: invalid User format '%v'", s)
	}
	return User{Identity: Identity{s[0:i], s[i+1:]}}, nil
}

func MustParseUser(s string) User {
	u, err := ParseUser(s)
	if err != nil {
		panic(err)
	}
	return u
}

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

// TokenInfo stores any RFC 2617 authorization token data,
// including custom provider tokens.
type TokenInfo struct {
	SchemeId string
	Values   url.Values
}

// NewTokenInfo creates a new TokenInfo instance.
func NewTokenInfo(schemeId string) *TokenInfo {
	return &TokenInfo{
		SchemeId: schemeId,
		Values:   url.Values{},
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
		return nil, fmt.Errorf("Malformed authentication header: %s", header)
	}
	schemeId := parts[0]
	paramString := parts[1]

	token := &TokenInfo{SchemeId: schemeId, Values: url.Values{}}
	parts = strings.Split(paramString, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		kvpair := strings.Split(part, "=")
		if len(kvpair) != 2 {
			return nil, fmt.Errorf("Malformed authentication param: %s", part)
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
	fmt.Fprintf(&buf, "%s", t.SchemeId)
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

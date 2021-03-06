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
	"fmt"
	"net/http"
	"os"

	"code.google.com/p/go.crypto/ssh/terminal"
)

// PasswordProvider obtains a password for authentication providers
// that need one in order to generate an auth token.
type PasswordProvider interface {
	// Password obtains the password string and any error that occurred
	// in the process.
	Password() (string, error)
}

// PasswordPrompter obtains a password for authentication
// by prompting for input on the current terminal device.
type PasswordPrompter struct{}

func (pp *PasswordPrompter) Password() (string, error) {
	fd := int(os.Stdin.Fd())
	if !terminal.IsTerminal(fd) {
		return "", fmt.Errorf("cannot read password input: not a terminal")
	}

	// Put terminal in raw mode
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer terminal.Restore(fd, oldState)

	_, err = fmt.Printf("Password: ")
	if err != nil {
		return "", err
	}

	// Line feed after password entered, since input is suppressed.
	defer fmt.Println()

	// Read the password
	pass, err := terminal.ReadPassword(fd)
	return string(pass), err
}

// PasswordUnavilable is never able to obtain a password.
type PasswordUnavailable struct{}

func (pu *PasswordUnavailable) Password() (string, error) {
	return "", fmt.Errorf("password is unavailable")
}

var ErrUnauthorized error = fmt.Errorf("http request not authorized")

// Scheme is a system which identifies principal user identities, and
// provides a means for those users to prove their identity.
type Scheme interface {

	// Name returns the locally bound name for this scheme.
	Name() string

	// Authenticate checks an HTTP request for a positive identity.
	// Returns the user identity if authentication is valid, otherwise
	// ErrUnauthorized as a prompt to authenticate.
	Authenticate(r *http.Request) (principal Principal, err error)
}

// TokenScheme creates authorization tokens for identities and validates them.
type TokenScheme interface {
	Scheme

	// Authorize creates an authorization token for the given identity.
	// Implementations may support multiple factors
	// (passphrases, private keys, etc.) when creating the authorization.
	Authorize(principal Principal) (token *TokenInfo, err error)

	// Validate checks an authorization token created by Authorize. If valid,
	// returns the user identity for whom it was created.
	Validate(token *TokenInfo) (principal Principal, err error)
}

// HandshakeScheme handles handshake identity protocols such as OpenID or OAuth 2
// for HTTP services.
type HandshakeScheme interface {
	Scheme

	// SignIn redirects to an identity provider, such as an OpenID or OAuth service.
	// This interaction requires the client to be a web browser in most cases.
	SignIn(w http.ResponseWriter, r *http.Request) (err error)

	// Authenticated handles a redirect to an application "callback" endpoint from the
	// identity provider. Implementations will typically create a session here for the
	// established identity.
	Authenticated(w http.ResponseWriter, r *http.Request)
}

// SchemeMap stores registered Scheme name-to-instance bindings.
type SchemeMap struct {
	schemes map[string]Scheme
}

// NewSchemeMap creates an empty SchemeMap.
func NewSchemeMap() *SchemeMap {
	return &SchemeMap{
		schemes: make(map[string]Scheme),
	}
}

// Register adds a scheme implementation to the map.
// A scheme can only be registered once. After that it
// cannot be replaced by another scheme.
func (sm *SchemeMap) Register(scheme Scheme) error {
	if s, has := sm.schemes[scheme.Name()]; has {
		return fmt.Errorf("scheme already registered: %q", s.Name())
	}
	sm.schemes[scheme.Name()] = scheme
	return nil
}

// Scheme retrieves the scheme by name.
func (sm *SchemeMap) Scheme(name string) Scheme {
	s, has := sm.schemes[name]
	if !has {
		return nil
	}
	return s
}

// HandshakeAll retrieves all registered handshake schemes.
func (sm *SchemeMap) HandshakeAll() []HandshakeScheme {
	var result []HandshakeScheme
	for _, v := range sm.schemes {
		if s, is := v.(HandshakeScheme); is {
			result = append(result, s)
		}
	}
	return result
}

// Token retrieves a token scheme by name, or nil.
func (sm *SchemeMap) Token(name string) TokenScheme {
	s, has := sm.schemes[name]
	if !has {
		return nil
	}
	if ts, is := s.(TokenScheme); is {
		return ts
	}
	return nil
}

// Handshake retrieves a handshake scheme by name, or nil.
func (sm *SchemeMap) Handshake(name string) HandshakeScheme {
	s, has := sm.schemes[name]
	if !has {
		return nil
	}
	if hs, is := s.(HandshakeScheme); is {
		return hs
	}
	return nil
}

// AuthRequestToken matches and validates RFC 2617 authorization headers
// as a principal user identity.
func AuthRequestToken(scheme TokenScheme, r *http.Request) (Principal, error) {
	auths, has := r.Header[http.CanonicalHeaderKey("Authorization")]
	if !has {
		return Principal{}, fmt.Errorf("request not authenticated")
	}
	for _, auth := range auths {
		// TODO: quick prefix check of the auth string might be faster
		token, err := ParseTokenInfo(auth)
		if err != nil {
			continue
		}
		if token.Scheme != scheme.Name() {
			continue
		}
		principal, err := scheme.Validate(token)
		if err != nil {
			continue
		}
		return principal, nil
	}
	return Principal{}, ErrUnauthorized
}

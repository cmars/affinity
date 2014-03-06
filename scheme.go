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

	"code.google.com/p/gopass"
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
	return gopass.GetPass("Password: ")
}

// PasswordUnavilable is never able to obtain a password.
type PasswordUnavailable struct{}

func (pu *PasswordUnavailable) Password() (string, error) {
	return "", fmt.Errorf("Password is unavailable")
}

var ErrUnauthorized error = fmt.Errorf("HTTP request not authorized")

// Scheme is a system which identifies principal user identities, and
// provides a means for those users to prove their identity.
type Scheme interface {

	// Name returns the locally bound name for this scheme.
	Name() string

	// Authenticate checks an HTTP request for a positive identity.
	// Returns the user identity if authentication is valid, otherwise
	// ErrUnauthorized as a prompt to authenticate.
	Authenticate(r *http.Request) (user User, err error)
}

// TokenScheme creates authorization tokens for identities and validates them.
type TokenScheme interface {
	Scheme

	// Authorize creates an authorization token for the given identity.
	// Implementations may support multiple factors
	// (passphrases, private keys, etc.) when creating the authorization.
	Authorize(user User) (token *TokenInfo, err error)

	// Validate checks an authorization token created by Authorize. If valid,
	// returns the user identity for whom it was created.
	Validate(token *TokenInfo) (user User, err error)
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
		return fmt.Errorf("Scheme [%s] already registered", s.Name())
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
func AuthRequestToken(scheme TokenScheme, r *http.Request) (User, error) {
	auths, has := r.Header[http.CanonicalHeaderKey("Authorization")]
	if !has {
		return User{}, fmt.Errorf("Request not authenticated")
	}
	for _, auth := range auths {
		// TODO: quick prefix check of the auth string might be faster
		token, err := ParseTokenInfo(auth)
		if err != nil {
			continue
		}
		if token.SchemeId != scheme.Name() {
			continue
		}
		user, err := scheme.Validate(token)
		if err != nil {
			continue
		}
		return user, nil
	}
	return User{}, ErrUnauthorized
}

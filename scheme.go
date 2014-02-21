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
	"net/http"
	"net/url"

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

// SchemeAuthorizer creates authorization tokens for a given identity.
type SchemeAuthorizer interface {
	// Auth obtains the authorization token parameters for the given identity.
	// Some implementations may support multiple factors
	// (passphrases, private keys, etc.) when creating the authorization.
	Auth(id string) (values url.Values, err error)
}

// VerifyHandler is a callback function which receives the user's identity
// during a SchemeAuthenticator handshake.
type VerifyHandler func(map[string]string)

// SchemeAuthenticator authenticates handshake identity protocols such as OpenID or OAuth 2.
type SchemeAuthenticator interface {
	Authenticate(w http.ResponseWriter, r *http.Request) bool
	Callback(w http.ResponseWriter, r *http.Request) (User, url.Values, error)
}

// SchemeValidator validates an authorization token obtained by SchemeAuthorizer.
type SchemeValidator interface {
	// Validate checks the authorization parameters are valid. If so, returns the
	// qualified user ID which created it.
	Validate(values url.Values) (id string, err error)
}

// Scheme is a system which identifies principal user identities, and
// provides a means for those users to prove their identity by authenticating
// to generate an authorization token for some purpose.
type Scheme interface {
	// Authenticator returns the authenticator service for this scheme
	// implementation.
	Authenticator() SchemeAuthenticator
	// Authorizer returns the authorization token service for this scheme
	// implementation.
	Authorizer() SchemeAuthorizer
	// Name returns the locally bound name for this scheme.
	Name() string
	// Validator returns the token validation service for this scheme
	// implementation.
	Validator() SchemeValidator
}

// SchemeMap stores registered Scheme name-to-instance bindings.
type SchemeMap map[string]Scheme

// Register adds a scheme implementation to the map.
func (sm SchemeMap) Register(scheme Scheme) {
	sm[scheme.Name()] = scheme
}

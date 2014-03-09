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

package client

import (
	"net/http"

	. "github.com/juju/affinity"
)

// AuthClient is an *http.Client that is able to automatically
// negotiate authentication with a server from an AuthStore.
type AuthClient struct {
	*http.Client
	Store AuthStore
}

// WantsAuth returns information on the authentication schemes
// a server is advertising. These are mandatory for an HTTP 401
// Not Authorized response, but may also be given in other responses.
func WantsAuth(resp *http.Response) []*TokenInfo {
	wwwAuths, has := resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")]
	if !has {
		return nil
	}
	var tokens []*TokenInfo
	for _, wwwAuth := range wwwAuths {
		token, err := ParseTokenInfo(wwwAuth)
		if err != nil {
			continue
		}
		tokens = append(tokens, token)
	}
	return tokens
}

// Authorize adds any stored auth tokens from the requested schemes to an *http.Request.
func (c *AuthClient) Authorize(req *http.Request, schemes []*TokenInfo) error {
	var err error
	// Update request with obtained credentials.
	req.Header.Del("Authorization")
	for _, scheme := range schemes {
		var token *TokenInfo
		token, err = c.Store.Get(scheme.SchemeId, req.Host)
		if err == ErrAuthNotFound {
			continue
		} else if err != nil {
			return err
		}
		req.Header.Add("Authorization", token.Serialize())
	}
	if len(req.Header["Authorization"]) == 0 {
		return ErrAuthNotFound
	}
	return nil
}

// Do performs an *http.Request and returns the *http.Response or
// any error that occurs, after automatically attempting to negotiate
// authentication with the server.
func (c *AuthClient) Do(req *http.Request) (resp *http.Response, err error) {
	resp, err = c.Client.Do(req)
	// Negotiate auth
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		// What kind of auth is the server asking for?
		schemes := WantsAuth(resp)
		if len(schemes) == 0 {
			// No more schemes are supported.
			return resp, err
		}
		// Re-attempt
		c.Authorize(req, schemes)
		resp, err = c.Client.Do(req)
	}
	return resp, err
}

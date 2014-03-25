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

// The common provider package contains all of the cross-provider functionality.
package common

// This file contains all of the common openid functionality

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"code.google.com/p/go-uuid/uuid"
	"github.com/gorilla/sessions"
	"github.com/kushaldas/openid.go/src/openid"

	"github.com/juju/affinity"
)

type OpenID struct {
	nonceStore     *openid.SimpleNonceStore
	discoveryCache *openid.SimpleDiscoveryCache
	urlStore       map[string]string
	realm          string
	sessionStore   sessions.Store
	redirectHost   string
}

// NewSimpleOpenID creates a new OpenID authentication helper which facilitates
// establishing an identity and associating it with a secure session
// cookie. When redirectHost is "", OpenID redirects will use the same hostname
// as the request.
func NewSimpleOpenID(realm string, redirectHost string, sessionStore sessions.Store) *OpenID {
	return &OpenID{
		nonceStore:     &openid.SimpleNonceStore{Store: make(map[string][]*openid.Nonce)},
		discoveryCache: &openid.SimpleDiscoveryCache{},
		urlStore:       make(map[string]string), // TODO: needs to expire handshakes
		realm:          realm,
		sessionStore:   sessionStore,
		redirectHost:   redirectHost,
	}
}

func (oid *OpenID) respError(w http.ResponseWriter, msg string, statusCode int, cause error) {
	log.Println(cause)
	http.Error(w, msg, statusCode)
	return
}

func (oid *OpenID) responseHost(r *http.Request) string {
	host := oid.redirectHost
	if host == "" {
		host = r.Host
	}
	return host
}

func (oid *OpenID) Callback(w http.ResponseWriter, r *http.Request) {
	// verify the response
	fullURL := fmt.Sprintf("https://%v%v", oid.responseHost(r), r.URL.String())
	_, err := openid.Verify(fullURL, oid.discoveryCache, oid.nonceStore)
	if err != nil {
		oid.respError(w, "Unauthorized", http.StatusUnauthorized,
			fmt.Errorf("OpenID verification failed: %v", err))
		return
	}

	// verified then find the original stored url and redirect the use back to their original request
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		oid.respError(w, "Server error", http.StatusInternalServerError,
			fmt.Errorf("Failed to parse URL query string: %v", r.URL))
		return
	}

	returnTo := values.Get("openid.return_to")
	if returnTo == "" {
		oid.respError(w, "Server error", http.StatusInternalServerError,
			fmt.Errorf("openid.return_to not set in callback: %v", values))
		return
	}

	cbuuid := values.Get("cbuuid")
	if cbuuid == "" {
		oid.respError(w, "Server error", http.StatusInternalServerError,
			fmt.Errorf("cbuuid not set in callback: %v", values))
		return
	}

	originalUrl, ok := oid.urlStore[cbuuid]
	if !ok {
		oid.respError(w, "Server error", http.StatusInternalServerError,
			fmt.Errorf("cbuuid %v not found in local store", cbuuid))
		return
	}

	// We're done with the callback, remove it.
	// TODO: we should use an expiring kv store for these to prevent DoS.
	delete(oid.urlStore, cbuuid)

	_, ok = values["openid.sreg.email"]
	if !ok {
		oid.respError(w, "Server error", http.StatusInternalServerError,
			fmt.Errorf("openid.sreq.email missing from OpenID response"))
		return
	}

	session, err := oid.sessionStore.Get(r, oid.realm)
	if err != nil {
		oid.respError(w, "Server error", http.StatusInternalServerError,
			fmt.Errorf("Failed to get session: %v", err))
		return
	}

	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // One week
		Secure:   true,      // Enforce https, same-origin policy
		HttpOnly: true,      // http://blog.codinghorror.com/protecting-your-cookies-httponly/
	}
	for k, v := range values {
		session.Values[k] = v
	}
	err = sessions.Save(r, w)
	if err != nil {
		oid.respError(w, "Server error", http.StatusInternalServerError,
			fmt.Errorf("Failed to save session: %v", err))
		return
	}

	http.Redirect(w, r, originalUrl, http.StatusSeeOther)
}

func (oid *OpenID) Authenticate(r *http.Request) (*sessions.Session, error) {
	session, err := oid.sessionStore.Get(r, oid.realm)
	if err != nil {
		return nil, err
	}
	if session.IsNew || oid.Email(session) == "" {
		return nil, affinity.ErrUnauthorized
	}
	return session, nil
}

func (oid *OpenID) Email(session *sessions.Session) string {
	email, has := session.Values["openid.sreg.email"]
	if !has {
		return ""
	}
	s, is := email.([]string)
	if !is {
		return ""
	}
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func (oid *OpenID) OpRedirect(authorityURL string, w http.ResponseWriter, r *http.Request) error {
	// not present. redirect to authority for authentication
	cbuuid := uuid.NewRandom()

	// store the original user requested url
	originalUrl := fmt.Sprintf("https://%v%v", oid.responseHost(r), r.URL.String())
	oid.urlStore[cbuuid.String()] = originalUrl

	// now redirect to the authority
	fullURL := fmt.Sprintf("https://%v%v?cbuuid=%v", oid.responseHost(r), "/openidcallback", cbuuid)
	if redirectUrl, err := openid.RedirectUrl(authorityURL, fullURL, ""); err == nil {
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		return nil
	} else {
		return err
	}
}

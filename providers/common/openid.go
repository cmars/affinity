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
	"time"

	"code.google.com/p/go-uuid/uuid"
	"github.com/kushaldas/openid.go/src/openid"

	"github.com/juju/affinity"
)

var (
	nonceStore     = &openid.SimpleNonceStore{Store: make(map[string][]*openid.Nonce)}
	discoveryCache = &openid.SimpleDiscoveryCache{}
	urlStore       = make(map[string]string)
)

func Callback(w http.ResponseWriter, r *http.Request, onVerify affinity.VerifyHandler) {
	// verify the response
	fullURL := fmt.Sprintf("%v://%v%v", r.URL.Scheme, r.Host, r.URL.String())
	id, err := openid.Verify(fullURL, discoveryCache, nonceStore)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}

	// verified then find the original stored url and redirect the use back to their original request
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		log.Println("Failed to parse URL query string:", r.URL)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	returnTo := values.Get("openid.return_to")
	if returnTo == "" {
		log.Println("openid.return_to not set in callback: ", values)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	cbuuid := values.Get("cbuuid")
	if cbuuid == "" {
		log.Println("cbuuid not set in callback: ", values)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	originalUrl, ok := urlStore[cbuuid]
	if !ok {
		log.Println("cbuuid", cbuuid, "not found in local store")
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if onVerify != nil {
		onVerify(id)
	}

	delete(urlStore, cbuuid)
	expiration := time.Now().Add(time.Hour * 24)
	cookieUrl, _ := url.Parse(originalUrl)

	cookie := http.Cookie{
		Name:    "washed",
		Value:   "true",
		Path:    "/",
		Domain:  cookieUrl.Host,
		Expires: expiration}

	http.SetCookie(w, &cookie)

	http.Redirect(w, r, originalUrl, http.StatusSeeOther)
}

func Authenticate(authorityURL string, w http.ResponseWriter, r *http.Request) (bool, error) {

	// check for cookie holding flag
	if washed(r.Cookies()) {
		return true, nil
	}

	// not present. redirect to authority for authentication
	cbuuid := uuid.NewRandom()

	// store the original user requested url
	originalUrl := fmt.Sprintf("%v://%v%v", r.URL.Scheme, r.Host, r.URL.String())
	urlStore[cbuuid.String()] = originalUrl

	// now redirect to the authority
	fullURL := fmt.Sprintf("%v://%v%v?cbuuid=%v", r.URL.Scheme, r.Host, "/openidcallback", cbuuid)
	redirectUrl, err := openid.RedirectUrl(authorityURL, fullURL, "")

	if err == nil {
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		return true, nil
	}
	return false, err
}

// washed checks for and returns the washed cookie value, defaulting to false.
func washed(cookies []*http.Cookie) bool {
	for _, cookie := range cookies {
		if cookie.Name == "washed" {
			return cookie.Value == "true"
		}
	}
	return false
}

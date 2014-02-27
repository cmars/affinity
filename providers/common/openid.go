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
	"net/http"
	"net/url"
	"strings"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"github.com/kushaldas/openid.go/src/openid"
)

var (
	nonceStore     = &openid.SimpleNonceStore{Store: make(map[string][]*openid.Nonce)}
	discoveryCache = &openid.SimpleDiscoveryCache{}
	urlStore       = make(map[string]string)
)

func Callback(w http.ResponseWriter, r *http.Request) {
	// verify the response
	fullURL := fmt.Sprintf("http://%v%v", r.Host, r.URL.String())
	_, err := openid.Verify(fullURL, discoveryCache, nonceStore)

	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}

	// verified then find the original stored url and redirect the use back to their original request
	values, err := url.ParseQuery(r.URL.String())
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	returnTo, ok := values["openid.return_to"]

	if !ok {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// the url will be in the form http://<server>:<port>/openidcallback/cbuuid=<uuid>
	// so do the cheap thing and split on =
	splitData := strings.Split(returnTo[0], "=")

	if len(splitData) < 2 {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	cbuuid := splitData[len(splitData)-1]
	originalUrl, ok := urlStore[cbuuid]
	if !ok {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
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

	emailId, ok := values["openid.sreg.email"]
	if !ok {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// TODO look up the emailId in affinity and replace with a affinity obfuscated id
	affinityId := emailId[0]

	cookie = http.Cookie{
		Name:    "affinityId",
		Value:   affinityId,
		Path:    "/",
		Domain:  cookieUrl.Host,
		Expires: expiration}

	http.SetCookie(w, &cookie)

	http.Redirect(w, r, originalUrl, http.StatusSeeOther)

}

func Authenticate(authorityURL string, w http.ResponseWriter, r *http.Request) bool {

	// check for cookie holding flag
	if washed(r.Cookies()) {
		return true
	}

	// not present. redirect to authority for authentication
	cbuuid := uuid.NewRandom()

	// store the original user requested url
	originalUrl := fmt.Sprintf("http://%v%v", r.Host, r.URL.String())
	urlStore[cbuuid.String()] = originalUrl

	// now redirect to the authority
	fullURL := fmt.Sprintf("http://%v%v/cbuuid=%v", r.Host, "/openidcallback", cbuuid)
	redirectUrl, err := openid.RedirectUrl(authorityURL, fullURL, "")

	if err == nil {
		http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
		return true
	} else {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return false
	}

	return true
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

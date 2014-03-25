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

package usso

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
	"launchpad.net/usso"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/providers/common"
)

type scheme struct {
	token string
}

func (s *scheme) Name() string { return "usso" }

type tokenScheme struct {
	scheme
	passProv PasswordProvider
	token    string
}

type handshakeScheme struct {
	scheme
	openID *common.OpenID
}

// NewOpenIDWeb creates a new Ubuntu SSO OpenID authentication helper.  When
// redirectHost is "", OpenID redirects will use the same hostname as the
// request.
func NewOpenIdWeb(token string, redirectHost string, sessionStore sessions.Store) HandshakeScheme {
	return &handshakeScheme{
		scheme: scheme{
			token: token,
		},
		openID: common.NewSimpleOpenID(token, redirectHost, sessionStore),
	}
}

func NewOauthCli(token string, passProv PasswordProvider) TokenScheme {
	return &tokenScheme{
		scheme: scheme{
			token: token,
		},
		passProv: passProv,
	}
}

func (s *handshakeScheme) Authenticate(r *http.Request) (User, error) {
	session, err := s.openID.Authenticate(r)
	if err != nil {
		return User{}, err
	}
	return User{Identity{Scheme: s.Name(), Id: s.openID.Email(session)}}, nil
}

func (s *handshakeScheme) SignIn(w http.ResponseWriter, r *http.Request) error {
	return s.openID.OpRedirect(usso.ProductionUbuntuSSOServer.LoginURL(), w, r)
}

func (s *handshakeScheme) Authenticated(w http.ResponseWriter, r *http.Request) {
	s.openID.Callback(w, r)
}

func (s *tokenScheme) Authenticate(r *http.Request) (User, error) {
	return AuthRequestToken(s, r)
}

func (s *tokenScheme) Authorize(user User) (token *TokenInfo, err error) {
	if user.Identity.Scheme != s.Name() {
		return nil, fmt.Errorf("Cannot authorize scheme %s", user.Identity.Scheme)
	}

	pass, err := s.passProv.Password()
	if err != nil {
		return nil, err
	}

	ssoData, err := usso.ProductionUbuntuSSOServer.GetToken(user.Identity.Id, pass, s.token)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		SchemeId: s.Name(),
		Values: url.Values{
			"ConsumerKey":    []string{ssoData.ConsumerKey},
			"ConsumerSecret": []string{ssoData.ConsumerSecret},
			"TokenKey":       []string{ssoData.TokenKey},
			"TokenName":      []string{ssoData.TokenName},
			"TokenSecret":    []string{ssoData.TokenSecret},
		},
	}, nil
}

func (s *tokenScheme) Validate(token *TokenInfo) (User, error) {
	var err error
	luser := User{}
	if token.SchemeId != s.Name() {
		return luser, fmt.Errorf("%s: Not an Ubuntu SSO token", token.SchemeId)
	}
	consumerKey := token.Values.Get("ConsumerKey")
	if consumerKey == "" {
		err = fmt.Errorf("No ConsumerKey provided in authorization")
		return luser, err
	}
	consumerSecret := token.Values.Get("ConsumerSecret")
	if consumerSecret == "" {
		err = fmt.Errorf("No ConsumerSecret provided in authorization")
		return luser, err
	}
	tokenKey := token.Values.Get("TokenKey")
	if tokenKey == "" {
		err = fmt.Errorf("No TokenKey provided in authorization")
		return luser, err
	}
	tokenSecret := token.Values.Get("TokenSecret")
	if tokenSecret == "" {
		err = fmt.Errorf("No TokenSecret provided in authorization")
		return luser, err
	}
	tokenName := token.Values.Get("TokenName")
	if tokenName == "" {
		err = fmt.Errorf("No TokenName provided in authorization")
		return luser, err
	}
	// construct sso data collection for validation
	ssoData := usso.SSOData{
		ConsumerKey:    consumerKey,
		ConsumerSecret: consumerSecret,
		TokenKey:       tokenKey,
		TokenSecret:    tokenSecret,
		TokenName:      tokenName,
	}
	resultRaw, err := usso.ProductionUbuntuSSOServer.GetAccounts(&ssoData)
	if err != nil {
		log.Printf("Failed to validate USSO token data: %v", err)
		return luser, err
	}
	result := map[string]interface{}{}
	err = json.Unmarshal([]byte(resultRaw), &result)
	if err != nil {
		log.Printf("Failed to decode USSO data: %v", err)
		return luser, err
	}

	// check if the USS response has the necessary fields
	_, hasEmail := result["email"]
	_, hasDisplayName := result["displayname"]
	_, hasTokens := result["tokens"]
	if !hasEmail || !hasDisplayName || !hasTokens {
		err = fmt.Errorf("SSO validation failed, missing required fields")
		return luser, err
	}
	email, ok := result["email"].(string)
	if !ok || email == "" {
		err = fmt.Errorf("Invalid SSO data received for %v", result["email"])
		return luser, err
	}
	return User{Identity{Scheme: s.Name(), Id: email}}, nil
}

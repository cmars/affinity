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

	"launchpad.net/usso"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/providers/common"
)

type UssoScheme struct {
	PasswordProvider PasswordProvider
	Token            string
	OpenID           *common.OpenID
}

func NewOpenIdWeb(token string) *UssoScheme {
	return &UssoScheme{
		PasswordProvider: &PasswordUnavailable{},
		Token:            token,
		OpenID:           common.NewSimpleOpenID(token),
	}
}

func NewOauthCli(token string) *UssoScheme {
	return &UssoScheme{
		PasswordProvider: &PasswordPrompter{},
		Token:            token,
	}
}

func (s *UssoScheme) Callback(w http.ResponseWriter, r *http.Request) (User, *TokenInfo, error) {
	if s.OpenID == nil {
		return User{}, nil, fmt.Errorf("OpenID not supported")
	}

	var user User
	token := NewTokenInfo(s.Name())
	err := fmt.Errorf("Failed to authenticate")
	s.OpenID.Callback(w, r, func(id map[string]string) {
		user = User{Identity: Identity{Scheme: s.Name(), Id: id["email"]}, TokenInfo: token}
		for k, v := range id {
			token.Values.Add(k, v)
		}
		err = nil
	})
	return user, token, err
}

func (s *UssoScheme) Authenticate(w http.ResponseWriter, r *http.Request) bool {
	if s.OpenID == nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Println(fmt.Errorf("OpenID not supported"))
		return false
	}

	rv, err := s.OpenID.Authenticate(usso.ProductionUbuntuSSOServer.LoginURL(), w, r)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Println(err)
		return false
	}
	return rv
}

func (s *UssoScheme) Auth(id string) (token *TokenInfo, err error) {
	pass, err := s.PasswordProvider.Password()
	if err != nil {
		return nil, err
	}

	ssoData, err := usso.ProductionUbuntuSSOServer.GetToken(id, pass, s.Token)
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

func (s *UssoScheme) Validate(token *TokenInfo) (id string, err error) {
	if token.SchemeId != s.Name() {
		return "", fmt.Errorf("%s: Not an Ubuntu SSO token", token.SchemeId)
	}
	consumerKey := token.Values.Get("ConsumerKey")
	if consumerKey == "" {
		err = fmt.Errorf("No ConsumerKey provided in authorization")
		return "", err
	}
	consumerSecret := token.Values.Get("ConsumerSecret")
	if consumerSecret == "" {
		err = fmt.Errorf("No ConsumerSecret provided in authorization")
		return "", err
	}
	tokenKey := token.Values.Get("TokenKey")
	if tokenKey == "" {
		err = fmt.Errorf("No TokenKey provided in authorization")
		return "", err
	}
	tokenSecret := token.Values.Get("TokenSecret")
	if tokenSecret == "" {
		err = fmt.Errorf("No TokenSecret provided in authorization")
		return "", err
	}
	tokenName := token.Values.Get("TokenName")
	if tokenName == "" {
		err = fmt.Errorf("No TokenName provided in authorization")
		return "", err
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
		return "", err
	}
	result := map[string]interface{}{}
	err = json.Unmarshal([]byte(resultRaw), &result)
	if err != nil {
		log.Printf("Failed to decode USSO data: %v", err)
		return "", err
	}

	// check if the USS response has the necessary fields
	_, hasEmail := result["email"]
	_, hasDisplayName := result["displayname"]
	_, hasTokens := result["tokens"]
	if !hasEmail || !hasDisplayName || !hasTokens {
		err = fmt.Errorf("SSO validation failed, missing required fields")
		return "", err
	}
	email, ok := result["email"].(string)
	if !ok || email == "" {
		err = fmt.Errorf("Invalid SSO data received for %v", result["email"])
		return "", err
	}
	return email, nil
}

func (s *UssoScheme) Authorizer() SchemeAuthorizer { return s }

func (s *UssoScheme) Authenticator() SchemeAuthenticator { return s }

func (s *UssoScheme) Validator() SchemeValidator { return s }

func (s *UssoScheme) Name() string { return "usso" }

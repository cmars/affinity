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

package server

import (
	"bytes"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/juju/affinity"
	"github.com/juju/affinity/rbac"
)

type Response struct {
	bytes.Buffer
	StatusCode int
	Error      error
}

func (r *Response) Send(w http.ResponseWriter) {
	if r.Error != nil {
		log.Println(r.Error)
		if r.StatusCode == 0 {
			r.StatusCode = 400
		}
	}
	if r.StatusCode != 0 {
		w.WriteHeader(r.StatusCode)
	}
	w.Write(r.Bytes())
}

type AuthServer struct {
	*mux.Router
	Store   rbac.FactStore
	Schemes *affinity.SchemeMap
}

func NewAuthServer(store rbac.FactStore) *AuthServer {
	return &AuthServer{mux.NewRouter(), store, affinity.NewSchemeMap()}
}

func (s *AuthServer) Authenticate(r *http.Request) (user affinity.Principal, err error) {
	auths, has := r.Header[http.CanonicalHeaderKey("Authorization")]
	if !has {
		// If the request does not have an authorization header,
		// fallback on the handshake method.
		for _, scheme := range s.Schemes.HandshakeAll() {
			user, err := scheme.Authenticate(r)
			if err != nil {
				return user, err
			}
		}
		return affinity.Principal{}, affinity.ErrUnauthorized
	}
	for _, auth := range auths {
		token, err := affinity.ParseTokenInfo(auth)
		if err != nil {
			continue
		}
		scheme := s.Schemes.Token(token.Scheme)
		if scheme == nil {
			continue
		}
		user, err := scheme.Authenticate(r)
		if err != nil {
			continue
		}
		return user, nil
	}
	return affinity.Principal{}, affinity.ErrUnauthorized
}

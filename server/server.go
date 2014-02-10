/*
   Affinity - Private groups as a service
   Copyright (C) 2014  Canonical, Ltd.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	. "github.com/cmars/affinity"
	"github.com/cmars/affinity/group"
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

type Server struct {
	*mux.Router
	store   Store
	schemes SchemeMap
}

func NewServer(store Store) *Server {
	s := &Server{mux.NewRouter(), store, make(SchemeMap)}
	s.HandleFunc("/{group}/", s.HandleGroup)
	s.HandleFunc("/{group}/{user}/", s.HandleUser)
	return s
}

func (s *Server) RegisterScheme(scheme Scheme) {
	s.schemes[scheme.Name()] = scheme
}

func (s *Server) Authenticate(r *http.Request) (user User, err error) {
	authStr := r.Header.Get("Authorization")
	if authStr == "" {
		return User{}, fmt.Errorf("Request not authenticated")
	}
	values, err := url.ParseQuery(authStr)
	if err != nil {
		return User{}, err
	}
	schemeId := values.Get("Affinity-Scheme")
	if schemeId == "" {
		return User{}, fmt.Errorf("Scheme not specified")
	}
	scheme, has := s.schemes[schemeId]
	if !has {
		return User{}, fmt.Errorf("unsupported scheme:", schemeId)
	}
	userId, err := scheme.Validator().Validate(values)
	if err != nil {
		return User{}, err
	}
	user = User{Identity{schemeId, userId}}
	if user.Wildcard() {
		return User{}, fmt.Errorf("Cannot authenticate a wildcard user")
	}
	return user, nil
}

func (s *Server) HandleGroup(w http.ResponseWriter, r *http.Request) {
	resp := s.handleGroup(r)
	resp.Send(w)
}

func (s *Server) handleGroup(r *http.Request) *Response {
	log.Println(r)
	vars := mux.Vars(r)
	groupId := vars["group"]
	authUser, err := s.Authenticate(r)
	if err != nil {
		return &Response{
			Error:      fmt.Errorf("auth failed: %v", err),
			StatusCode: http.StatusUnauthorized,
		}
	}

	groupSrv := group.NewGroupService(s.store, authUser)

	switch r.Method {
	case "PUT":
		err = groupSrv.AddGroup(groupId)
		return &Response{Error: err}
	case "GET":
		g, err := groupSrv.Group(groupId)
		if err != nil {
			return &Response{Error: err}
		}
		out, err := json.Marshal(g)
		resp := &Response{Error: err}
		resp.Write(out)
		return resp
	case "DELETE":
		err = groupSrv.RemoveGroup(groupId)
		return &Response{Error: err}
	}
	return &Response{
		Error:      fmt.Errorf("unsupported HTTP method: %v", r.Method),
		StatusCode: http.StatusMethodNotAllowed,
	}
}

func (s *Server) HandleUser(w http.ResponseWriter, r *http.Request) {
	resp := s.handleUser(r)
	resp.Send(w)
}

func (s *Server) handleUser(r *http.Request) *Response {
	log.Println(r)
	vars := mux.Vars(r)
	groupId := vars["group"]
	userString := vars["user"]
	user, err := ParseUser(userString)
	if err != nil {
		return &Response{Error: err}
	}

	_, has := s.schemes[user.Scheme]
	if !has {
		return &Response{Error: fmt.Errorf("unsupported scheme: %s", user.Scheme)}
	}

	authUser, err := s.Authenticate(r)
	if err != nil {
		return &Response{
			Error:      fmt.Errorf("auth failed: %v", err),
			StatusCode: http.StatusUnauthorized,
		}
	}

	groupSrv := group.NewGroupService(s.store, authUser)

	switch r.Method {
	case "GET":
		has, err := groupSrv.CheckMember(groupId, user)
		if err != nil {
			return &Response{Error: err}
		}
		if !has {
			return &Response{StatusCode: http.StatusNotFound}
		}
		return &Response{}
	case "PUT":
		err = groupSrv.AddMember(groupId, user)
		return &Response{Error: err}
	case "DELETE":
		err = groupSrv.RemoveMember(groupId, user)
		return &Response{Error: err}
	}
	return &Response{
		Error:      fmt.Errorf("unsupported HTTP method: %s", r.Method),
		StatusCode: http.StatusMethodNotAllowed,
	}
}

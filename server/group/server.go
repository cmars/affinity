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
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/juju/affinity"
	"github.com/juju/affinity/group"
	"github.com/juju/affinity/rbac"
	"github.com/juju/affinity/server"
)

// GroupServer exposes affinity's principal group management over a RESTful API.
type GroupServer struct {
	*server.AuthServer
}

func NewGroupServer(store rbac.FactStore) *GroupServer {
	s := &GroupServer{server.NewAuthServer(store)}
	s.HandleFunc("/{group}/", s.HandleGroup)
	s.HandleFunc("/{group}/{user}/", s.HandleUser)
	return s
}

func (s *GroupServer) HandleGroup(w http.ResponseWriter, r *http.Request) {
	resp := s.handleGroup(r)
	resp.Send(w)
}

func (s *GroupServer) handleGroup(r *http.Request) *server.Response {
	log.Println(r)
	vars := mux.Vars(r)
	g := affinity.Principal{Scheme: group.SchemeName, Id: vars["group"]}

	authUser, err := s.Authenticate(r)
	if err != nil {
		return &server.Response{
			Error:      fmt.Errorf("auth failed: %q", err),
			StatusCode: http.StatusUnauthorized,
		}
	}

	groupSrv := group.NewGroupService(s.Store, authUser)

	switch r.Method {
	case "PUT":
		err = groupSrv.AddGroup(g)
		return &server.Response{Error: err}
	case "GET":
		resp := &server.Response{Error: err}
		resp.Write([]byte(g.String()))
		return resp
	case "DELETE":
		err = groupSrv.RemoveGroup(g)
		return &server.Response{Error: err}
	}
	return &server.Response{
		Error:      fmt.Errorf("unsupported HTTP method: %q", r.Method),
		StatusCode: http.StatusMethodNotAllowed,
	}
}

func (s *GroupServer) HandleUser(w http.ResponseWriter, r *http.Request) {
	resp := s.handleUser(r)
	resp.Send(w)
}

func (s *GroupServer) handleUser(r *http.Request) *server.Response {
	log.Println(r)
	vars := mux.Vars(r)
	g := affinity.Principal{Scheme: group.SchemeName, Id: vars["group"]}
	userString := vars["user"]
	user, err := affinity.ParsePrincipal(userString)
	if err != nil {
		return &server.Response{Error: err}
	}

	authUser, err := s.Authenticate(r)
	if err != nil {
		return &server.Response{
			Error:      fmt.Errorf("auth failed: %q", err),
			StatusCode: http.StatusUnauthorized,
		}
	}

	groupSrv := group.NewGroupService(s.Store, authUser)

	switch r.Method {
	case "GET":
		has, err := groupSrv.CheckMember(g, user)
		if err != nil {
			return &server.Response{Error: err}
		}
		if !has {
			return &server.Response{StatusCode: http.StatusNotFound}
		}
		return &server.Response{}
	case "PUT":
		err = groupSrv.AddMember(g, user)
		return &server.Response{Error: err}
	case "DELETE":
		err = groupSrv.RemoveMember(g, user)
		return &server.Response{Error: err}
	}
	return &server.Response{
		Error:      fmt.Errorf("unsupported HTTP method: %q", r.Method),
		StatusCode: http.StatusMethodNotAllowed,
	}
}

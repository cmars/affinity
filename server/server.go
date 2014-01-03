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
	s.HandleFunc("/{group}/{scheme}:{user}", s.HandleUser)
	return s
}

func (s *Server) RegisterScheme(scheme Scheme) {
	s.schemes[scheme.Name()] = scheme
}

func (s *Server) Authenticate(r *http.Request) (schemeId, userId string, err error) {
	authStr := r.Header.Get("Authorization")
	if authStr == "" {
		return "", "", fmt.Errorf("Request not authenticated")
	}
	values, err := url.ParseQuery(authStr)
	if err != nil {
		return "", "", err
	}
	schemeId = values.Get("Affinity-Scheme")
	if schemeId == "" {
		return "", "", fmt.Errorf("Scheme not specified")
	}
	scheme, has := s.schemes[schemeId]
	if !has {
		return "", "", fmt.Errorf("unsupported scheme:", schemeId)
	}
	userId, err = scheme.Validator().Validate(values)
	return schemeId, userId, err
}

func (s *Server) HandleGroup(w http.ResponseWriter, r *http.Request) {
	resp := s.handleGroup(r)
	resp.Send(w)
}

func (s *Server) handleGroup(r *http.Request) *Response {
	log.Println(r)
	vars := mux.Vars(r)
	groupId := vars["group"]
	schemeId, userId, err := s.Authenticate(r)
	if err != nil {
		return &Response{
			Error:      fmt.Errorf("auth failed: %v", err),
			StatusCode: http.StatusUnauthorized,
		}
	}

	group, getErr := s.store.GetGroup(groupId)

	switch r.Method {
	case "PUT":
		if getErr != NotFound {
			if getErr == nil {
				return &Response{Error: fmt.Errorf("Cannot create group: already exists")}
			}
			return &Response{Error: getErr}
		}
		err = s.store.AddGroup(&Group{Id: groupId, Admins: []User{User{schemeId, userId}}})
		return &Response{Error: err}
	case "GET":
		if getErr != nil {
			return &Response{Error: getErr}
		}
		if !group.HasAdmin(User{schemeId, userId}) {
			return &Response{
				Error:      fmt.Errorf("not an admin of %s: %s:%s", groupId, schemeId, userId),
				StatusCode: http.StatusForbidden,
			}
		}
		out, err := json.Marshal(group)
		resp := &Response{Error: err}
		resp.Write(out)
	case "DELETE":
		if getErr != nil {
			return &Response{Error: getErr}
		}
		if !group.HasAdmin(User{schemeId, userId}) {
			return &Response{
				Error:      fmt.Errorf("not an admin of %s: %s:%s", groupId, schemeId, userId),
				StatusCode: http.StatusForbidden,
			}
		}
		return &Response{Error: s.store.DeleteGroup(groupId)}
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
	vars := mux.Vars(r)
	groupId := vars["group"]
	schemeId := vars["scheme"]
	userId := vars["user"]
	user := User{schemeId, userId}

	_, has := s.schemes[schemeId]
	if !has {
		return &Response{Error: fmt.Errorf("unsupported scheme: %s", schemeId)}
	}

	authSchemeId, authUserId, err := s.Authenticate(r)
	if err != nil {
		return &Response{
			Error:      fmt.Errorf("auth failed: %v", err),
			StatusCode: http.StatusUnauthorized,
		}
	}
	authUser := User{authSchemeId, authUserId}

	group, err := s.store.GetGroup(groupId)
	if err != nil {
		return &Response{Error: err}
	}

	switch r.Method {
	case "GET":
		if !group.HasAdmin(authUser) && !group.HasMember(authUser) {
			return &Response{
				Error: fmt.Errorf("auth user %s:%s: not allowed to check membership of %s:%s",
					authSchemeId, authSchemeId, schemeId, userId),
				StatusCode: http.StatusNotFound,
			}
		}
		if !group.HasAdmin(user) && !group.HasMember(user) {
			return &Response{StatusCode: http.StatusNotFound}
		}
		return &Response{}
	case "PUT":
		if !group.HasAdmin(authUser) {
			return &Response{
				Error: fmt.Errorf("cannot %s: %s:%s is not an admin of %s",
					r.Method, authSchemeId, authUserId, groupId),
				StatusCode: http.StatusForbidden}
		}
		err = s.store.AddMember(groupId, user)
	case "DELETE":
		if !group.HasAdmin(authUser) {
			return &Response{
				Error: fmt.Errorf("cannot %s: %s:%s is not an admin of %s",
					r.Method, authSchemeId, authUserId, groupId),
				StatusCode: http.StatusForbidden}
		}
		err = s.store.DeleteMember(groupId, user)
	default:
		return &Response{
			Error:      fmt.Errorf("unsupported HTTP method: %s", r.Method),
			StatusCode: http.StatusMethodNotAllowed}
	}
	return &Response{Error: err}
}

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

package server_test

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "launchpad.net/gocheck"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/rbac/storage/mem"
	"github.com/juju/affinity/server"
)

func TestServerSuite(t *testing.T) { TestingT(t) }

type ServerSuite struct {
	*httptest.Server
	currentUser Principal
}

var _ = Suite(&ServerSuite{})

type MockScheme struct{}

func (s *MockScheme) Name() string { return "mock" }

func (s *MockScheme) Authenticate(r *http.Request) (user Principal, err error) {
	return AuthRequestToken(s, r)
}

func (s *MockScheme) Authorize(user Principal) (token *TokenInfo, err error) {
	token = NewTokenInfo(s.Name())
	data := []byte(user.String())
	token.Values.Set("data", hex.EncodeToString(data))
	return token, nil
}

func (s *MockScheme) Validate(token *TokenInfo) (user Principal, err error) {
	data := token.Values.Get("data")
	if data == "" {
		return Principal{}, fmt.Errorf("no data")
	}
	dec, err := hex.DecodeString(data)
	if err != nil {
		return Principal{}, fmt.Errorf("bad data")
	}
	user, err = ParsePrincipal(string(dec))
	if err != nil {
		return Principal{}, fmt.Errorf("bad user data")
	}
	if user.Scheme != s.Name() {
		return Principal{}, fmt.Errorf("wrong scheme")
	}
	return user, nil
}

func (ss *ServerSuite) SetUpTest(c *C) {
	s := server.NewAuthServer(mem.NewFactStore())
	s.Schemes.Register(&MockScheme{})
	s.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		var err error
		ss.currentUser, err = s.Authenticate(r)
		if err == ErrUnauthorized {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	})
	ss.Server = httptest.NewServer(s)
}

func (ss *ServerSuite) TearDownTest(c *C) {
	ss.currentUser = Principal{}
	ss.Server.Close()
}

func (ss *ServerSuite) TestNoAuth(c *C) {
	res, err := http.Get(ss.URL + "/whoami")
	c.Check(err, IsNil)
	c.Check(res.StatusCode, Equals, 401)
}

func (ss *ServerSuite) TestBadAuth(c *C) {
	user, err := ParsePrincipal("mock:foo")
	c.Assert(err, IsNil)

	scheme := &MockScheme{}

	tokenInfo, err := scheme.Authorize(user)
	c.Assert(err, IsNil)

	req, err := http.NewRequest("GET", ss.URL+"/whoami", nil)
	c.Assert(err, IsNil)

	req.Header.Set("Authorization", tokenInfo.Serialize())

	res, err := http.DefaultClient.Do(req)
	c.Check(err, IsNil)
	c.Check(res.StatusCode, Equals, 200)
}

func (ss *ServerSuite) TestNotFound(c *C) {
	res, err := http.Get(ss.URL + "/whaaaagarbl")
	c.Check(err, IsNil)
	c.Check(res.StatusCode, Equals, 404)
}

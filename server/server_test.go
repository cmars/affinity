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
	"net/http"
	"net/http/httptest"
	"testing"

	. "launchpad.net/gocheck"

	. "github.com/juju/affinity/server"
	"github.com/juju/affinity/storage/mem"
)

func TestServerSuite(t *testing.T) { TestingT(t) }

type ServerSuite struct{}

var _ = Suite(&ServerSuite{})

func (ss *ServerSuite) TestServerApi(c *C) {
	s := NewServer(mem.NewStore())
	ts := httptest.NewServer(s)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	c.Check(err, IsNil)
	c.Check(res.StatusCode, Equals, 404)

	res, err = http.Get(ts.URL + "/foobar")
	c.Check(err, IsNil)
	c.Check(res.StatusCode, Equals, 404)
}

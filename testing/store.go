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

package testing

import (
	. "launchpad.net/gocheck"

	"github.com/juju/affinity/rbac"
)

type StoreTests struct {
	Store rbac.Store
}

func (s *StoreTests) SetUp(c *C) {
	for _, grant := range futuramaGrants {
		err := s.Store.InsertGrant(grant.principal, grant.role, grant.resource)
		c.Assert(err, IsNil)
	}
}

type StoreSuite struct {
	*StoreTests
}

func NewStoreSuite(s rbac.Store) *StoreSuite {
	return &StoreSuite{&StoreTests{s}}
}

type grantData struct {
	principal, role, resource string
}

var futuramaGrants []grantData = []grantData{
	{"test:scruffy", "janitor", "facilities:bucket"},
	{"test:leela", "pilot", "spacecraft:ship"},
	{"test:hermes", "bureaucrat", "bureaucracy:forms"},
	{"test:zoidberg", "doctor", "planet-express:crew"},

	{"test:fry", "passenger", "spacecraft:ship"},
	{"test:professor", "passenger", "spacecraft:ship"},
	{"test:bender", "passenger", "spacecraft:ship"},
	{"test:amy", "passenger", "spacecraft:ship"},
	{"test:hermes", "passenger", "spacecraft:ship"},
	{"test:zoidberg", "passenger", "spacecraft:ship"},
}

func (s *StoreTests) TestFlatGrantStore(c *C) {
	var has bool
	var err error
	has, err = s.Store.HasGrant("test:bender", "passenger", "spacecraft:ship", false)
	c.Assert(has, Equals, true)
	c.Assert(err, IsNil)

	has, err = s.Store.HasGrant("test:bender", "pilot", "spacecraft:ship", false)
	c.Assert(has, Equals, false)
	c.Assert(err, IsNil)

	has, err = s.Store.HasGrant("test:bender", "janitor", "facilities:bucket", false)
	c.Assert(has, Equals, false)
	c.Assert(err, IsNil)

	has, err = s.Store.HasGrant("test:santa_claus", "pilot", "spacecraft:ship", false)
	c.Assert(has, Equals, false)
	c.Assert(err, IsNil)
}

func (s *StoreTests) TestGroupGrants(c *C) {
	var has bool
	var err error
	// Let's create a deliver group
	s.Store.AddGroup("delivery-team")
	for _, employee := range []string{
		"test:fry", "test:leela", "test:bender", "test:amy",
	} {
		s.Store.AddMember("delivery-team", employee)
	}
	groups, err := s.Store.GroupsOf("test:fry", true)
	c.Assert(err, IsNil)
	c.Assert(groups, HasLen, 1)
	c.Assert(groups[0], Equals, "delivery-team")
	// Let's grant a role to the group
	err = s.Store.InsertGrant("delivery-team", "pickup-delivery", "planet-express:postbox")
	c.Assert(err, IsNil)
	// Fry should be able to pick up a delivery from a post box.
	has, err = s.Store.HasGrant("test:fry", "pickup-delivery", "planet-express:postbox", true)
	c.Assert(has, Equals, true)
	c.Assert(err, IsNil)
	// However this grant was to a team of which he is a member
	has, err = s.Store.HasGrant("test:fry", "pickup-delivery", "planet-express:postbox", false)
	c.Assert(has, Equals, false)
}

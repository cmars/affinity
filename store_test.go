package affinity_test

import (
	. "launchpad.net/gocheck"

	. "launchpad.net/go-affinity"
)

type StoreTests struct {
	Store Store
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

func NewStoreSuite(s Store) *StoreSuite {
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

func (s *StoreSuite) TestFlatGrantStore(c *C) {
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

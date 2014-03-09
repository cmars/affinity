package affinity_test

import (
	. "launchpad.net/gocheck"

	. "github.com/juju/affinity"
)

var id Identity = Identity{Scheme: "foo", Id: "bar"}

func (s *AffinitySuite) TestIdentityEquals(c *C) {
	c.Check(id.Equals(Identity{Scheme: "foo", Id: "bar"}), Equals, true)
	c.Check(id.Equals(Identity{Scheme: "bar", Id: "foo"}), Equals, false)
	c.Check(id.Equals(Identity{}), Equals, false)

	c.Check(id.String(), Equals, "foo:bar")

	schemeId, userId := id.SchemeId()
	c.Check(schemeId, Equals, id.Scheme)
	c.Check(userId, Equals, id.Id)
}

func (s *AffinitySuite) TestUserContains(c *C) {
	c.Check(User{Identity: id}.Contains(User{Identity: id}), Equals, true)
	c.Check(User{Identity: Identity{Scheme: "foo", Id: "*"}}.Contains(User{Identity: id}), Equals, true)
	c.Check(User{Identity: id}.Contains(User{Identity: Identity{Scheme: "foo", Id: "*"}}), Equals, false)
	// Does a wildcard of all wildcards contain itself?
	c.Check(User{Identity: Identity{Scheme: "foo", Id: "*"}}.Contains(User{Identity: Identity{Scheme: "foo", Id: "*"}}), Equals, true)
}

func (s *AffinitySuite) TestParseUser(c *C) {
	u, err := ParseUser("foo:bar")
	c.Check(err, IsNil)
	c.Check(u, Equals, User{Identity: id})

	u, err = ParseUser("bar:foo")
	c.Check(err, IsNil)
	c.Check(u, Not(Equals), User{Identity: id})

	u, err = ParseUser("foo:bar:baz")
	c.Check(err, IsNil)
	c.Check(u.Identity.Scheme, Equals, "foo")
	c.Check(u.Identity.Id, Equals, "bar:baz")

	_, err = ParseUser("foo:")
	c.Check(err, NotNil)
	c.Check(func() { MustParseUser("foo:") }, PanicMatches, "Parse error: invalid User format 'foo:'")

	_, err = ParseUser(":bar")
	c.Check(err, NotNil)
	c.Check(func() { MustParseUser(":bar") }, PanicMatches, "Parse error: invalid User format ':bar'")
}

func (s *AffinitySuite) TestGroupContains(c *C) {
	dolan := User{Identity: Identity{Scheme: "test", Id: "dolan"}}
	gooby := User{Identity: Identity{Scheme: "test", Id: "gooby"}}
	ducks := Group{Identity: Identity{Scheme: "test", Id: "ducks"}, Members: []Principal{dolan}}
	dogs := Group{Identity: Identity{Scheme: "test", Id: "dogs"}, Members: []Principal{gooby}}
	animals := Group{Identity: Identity{Scheme: "test", Id: "animals"}, Members: []Principal{ducks, dogs}}

	c.Check(ducks.Contains(dolan), Equals, true)
	c.Check(ducks.Contains(gooby), Equals, false)

	c.Check(dogs.Contains(dolan), Equals, false)
	c.Check(dogs.Contains(gooby), Equals, true)

	// Groups contain themselves. Convenient for matching.
	c.Check(dogs.Contains(dogs), Equals, true)
	c.Check(ducks.Contains(ducks), Equals, true)
	c.Check(animals.Contains(animals), Equals, true)

	c.Check(dogs.Contains(ducks), Equals, false)
	c.Check(ducks.Contains(dogs), Equals, false)

	c.Check(animals.Contains(ducks), Equals, true)
	c.Check(animals.Contains(dogs), Equals, true)
	c.Check(animals.Contains(dolan), Equals, true)
	c.Check(animals.Contains(gooby), Equals, true)
}

func (s *AffinitySuite) TestParseToken(c *C) {
	authString := `Wacky realm="bizarro", up="down", left="right"`
	token, err := ParseTokenInfo(authString)
	c.Check(err, IsNil)
	c.Check(token.Realm(), Equals, "bizarro")
	c.Check(token.Values.Get("realm"), Equals, "bizarro")
	c.Check(token.Values.Get("up"), Equals, "down")
	c.Check(token.Values.Get("left"), Equals, "right")
	c.Check(token.Values["left"], DeepEquals, []string{"right"})
	c.Check(token.Values.Get("orange"), Equals, "")
	token2, err := ParseTokenInfo(token.Serialize())
	c.Check(token, DeepEquals, token2)
}

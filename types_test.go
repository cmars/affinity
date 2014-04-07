package affinity_test

import (
	. "launchpad.net/gocheck"

	. "github.com/juju/affinity"
)

var testUser Principal = Principal{Scheme: "foo", Id: "bar"}

func (s *AffinitySuite) TestPrincipalEquals(c *C) {
	c.Check(testUser.Equals(Principal{Scheme: "foo", Id: "bar"}), Equals, true)
	c.Check(testUser.Equals(Principal{Scheme: "bar", Id: "foo"}), Equals, false)
	c.Check(testUser.Equals(Principal{}), Equals, false)

	c.Check(testUser.String(), Equals, "foo:bar")
}

func (s *AffinitySuite) TestUserContains(c *C) {
	p2 := testUser
	c.Check(testUser.Contains(p2), Equals, true)
	c.Check(Principal{Scheme: "foo", Id: "*"}.Contains(testUser), Equals, true)
	c.Check(testUser.Contains(Principal{Scheme: "foo", Id: "*"}), Equals, false)
	// Does a wildcard of all wildcards contain itself?
	c.Check(Principal{Scheme: "foo", Id: "*"}.Contains(Principal{Scheme: "foo", Id: "*"}), Equals, true)
}

func (s *AffinitySuite) TestParsePrincipal(c *C) {
	u, err := ParsePrincipal("foo:bar")
	c.Check(err, IsNil)
	c.Check(u, Equals, testUser)

	u, err = ParsePrincipal("bar:foo")
	c.Check(err, IsNil)
	c.Check(u, Not(Equals), testUser)

	u, err = ParsePrincipal("foo:bar:baz")
	c.Check(err, IsNil)
	c.Check(u.Scheme, Equals, "foo")
	c.Check(u.Id, Equals, "bar:baz")

	_, err = ParsePrincipal("foo:")
	c.Check(err, NotNil)
	c.Check(func() { MustParsePrincipal("foo:") }, PanicMatches, `parse error: invalid User format: "foo:"`)

	_, err = ParsePrincipal(":bar")
	c.Check(err, NotNil)
	c.Check(func() { MustParsePrincipal(":bar") }, PanicMatches, `parse error: invalid User format: ":bar"`)
}

/*
func (s *AffinitySuite) TestGroupContains(c *C) {
	dolan := Principal{Scheme: "test", Id: "dolan"}
	gooby := Principal{Scheme: "test", Id: "gooby"}
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
*/

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

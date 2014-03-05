package client_test

import (
	"net/http"
	"net/url"

	. "launchpad.net/gocheck"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/client"
)

func (s *ClientSuite) TestGetSetExists(c *C) {
	_, err := s.Store.Get("foo", "example.com")
	c.Check(err, NotNil)
	c.Assert(err, DeepEquals, client.ErrAuthNotFound)
	err = s.Store.Set(&TokenInfo{SchemeId: "foo", Values: url.Values{"secret": []string{"squirrel"}}}, "example.com")
	c.Assert(err, IsNil)
	token, err := s.Store.Get("foo", "example.com")
	c.Check(err, IsNil)
	c.Check(token.Values.Get("secret"), Equals, "squirrel")
}

func (s *ClientSuite) TestDistinctSchemesEndpoints(c *C) {
	var err error
	err = s.Store.Set(&TokenInfo{SchemeId: "foo", Values: url.Values{"secret": []string{"squirrel"}}}, "example.com")
	c.Assert(err, IsNil)
	err = s.Store.Set(&TokenInfo{SchemeId: "bar", Values: url.Values{"scooby": []string{"snack"}}}, "example.com")
	c.Assert(err, IsNil)

	err = s.Store.Set(&TokenInfo{SchemeId: "foo", Values: url.Values{"captain": []string{"caveman"}}}, "example.com:8080")
	c.Assert(err, IsNil)
	err = s.Store.Set(&TokenInfo{SchemeId: "bar", Values: url.Values{"hacksaw": []string{"duggan"}}}, "example.com:8080")
	c.Assert(err, IsNil)

	token, err := s.Store.Get("foo", "example.com")
	c.Check(err, IsNil)
	c.Check(token.Values.Get("secret"), Equals, "squirrel")

	token, err = s.Store.Get("bar", "example.com")
	c.Check(err, IsNil)
	c.Check(token.Values.Get("scooby"), Equals, "snack")

	token, err = s.Store.Get("foo", "example.com:8080")
	c.Check(err, IsNil)
	c.Check(token.Values.Get("secret"), Equals, "")
	c.Check(token.Values.Get("captain"), Equals, "caveman")

	token, err = s.Store.Get("bar", "example.com:8080")
	c.Check(err, IsNil)
	c.Check(token.Values.Get("hacksaw"), Equals, "duggan")

	_, err = s.Store.Get("baz", "example.com")
	c.Check(err, NotNil)

	_, err = s.Store.Get("bar", "example.com:8123")
	c.Check(err, NotNil)
}

func (s *ClientSuite) TestWantsAuth(c *C) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Add("WWW-Authenticate", `Foo secret="squirrel"`)
	resp.Header.Add("WWW-Authenticate", `Bar human="cannonball"`)
	tokens := client.WantsAuth(resp)
	c.Assert(tokens, HasLen, 2)
	var foo *TokenInfo
	var bar *TokenInfo
	for _, token := range tokens {
		switch token.SchemeId {
		case "Foo":
			foo = token
		case "Bar":
			bar = token
		default:
			c.Fail()
		}
	}
	c.Assert(foo, NotNil)
	c.Assert(bar, NotNil)
	c.Check(foo.Values.Get("secret"), Equals, "squirrel")
	c.Check(bar.Values.Get("human"), Equals, "cannonball")
}

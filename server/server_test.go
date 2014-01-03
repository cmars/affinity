package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "launchpad.net/gocheck"

	. "github.com/cmars/affinity/server"
)

func TestServerSuite(t *testing.T) { TestingT(t) }

type ServerSuite struct{}

var _ = Suite(&ServerSuite{})

func (ss *ServerSuite) TestServerApi(c *C) {
	s := NewServer(NewTestStore())
	ts := httptest.NewServer(s)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	c.Check(err, IsNil)
	c.Check(res.StatusCode, Equals, 404)

	res, err = http.Get(ts.URL + "/foobar")
	c.Check(err, IsNil)
	c.Check(res.StatusCode, Equals, 404)
}

package client_test

import (
	"testing"

	. "launchpad.net/gocheck"

	. "github.com/juju/affinity/client"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ClientSuite struct {
	Store AuthStore
}

var _ = Suite(&ClientSuite{})

func (s *ClientSuite) SetUpTest(c *C) {
	var err error
	s.Store, err = NewFileAuthStore(c.MkDir())
	c.Assert(err, IsNil)
}

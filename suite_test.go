package affinity_test

import (
	"testing"

	. "launchpad.net/gocheck"
)

type AffinitySuite struct {
	*StoreSuite
	*RbacSuite
}

func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&AffinitySuite{})

func (s *AffinitySuite) SetUpTest(c *C) {
	s.StoreSuite = NewStoreSuite(NewMemStore())
	s.StoreSuite.SetUp(c)
	s.RbacSuite = NewRbacSuite(NewMemStore())
	s.RbacSuite.SetUp(c)
}

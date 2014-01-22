package affinity_test

import (
	"testing"

	. "launchpad.net/gocheck"

	"launchpad.net/go-affinity/storage/mem"
)

type AffinitySuite struct {
	*StoreSuite
	*RbacSuite
}

func Test(t *testing.T) { TestingT(t) }

var _ = Suite(&AffinitySuite{})

func (s *AffinitySuite) SetUpTest(c *C) {
	s.StoreSuite = NewStoreSuite(mem.NewStore())
	s.StoreSuite.SetUp(c)
	s.RbacSuite = NewRbacSuite(mem.NewStore())
	s.RbacSuite.SetUp(c)
}

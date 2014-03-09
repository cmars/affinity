package util_test

import (
	"testing"

	. "launchpad.net/gocheck"

	"github.com/juju/affinity/util"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type UtilSuite struct{}

var _ = Suite(&UtilSuite{})

func (s *UtilSuite) TestUniqueStrings(c *C) {
	c.Check(util.UniqueStrings([]string{"foo", "foo", "bar", "bar", "bar", "baz"}), HasLen, 3)
	c.Check(util.UniqueStrings([]string{"foo", "bar", "baz"}), HasLen, 3)
	c.Check(util.UniqueStrings([]string{}), HasLen, 0)
}

func has(ss util.StringSet, value string) bool {
	_, result := ss[value]
	return result
}

func (s *UtilSuite) TestStringSet(c *C) {
	ss := util.NewStringSet([]string{"foo", "bar", "baz"})
	c.Check(has(ss, "foo"), Equals, true)
	c.Check(has(ss, "bar"), Equals, true)
	c.Check(has(ss, "baz"), Equals, true)
	c.Check(has(ss, "crabs"), Equals, false)
	ss2 := util.NewStringSet(nil)
	ss2.AddAll("foo", "bar", "baz")
	c.Check(ss, DeepEquals, ss2)
}

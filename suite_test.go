package affinity_test

import (
	"testing"

	. "launchpad.net/gocheck"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type AffinitySuite struct{}

var _ = Suite(&AffinitySuite{})

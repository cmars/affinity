/*
   Affinity - Private groups as a service
   Copyright (C) 2014  Canonical, Ltd.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

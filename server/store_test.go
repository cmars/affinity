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

package server_test

import (
	"fmt"
	"testing"

	. "launchpad.net/gocheck"

	. "github.com/cmars/affinity"
	. "github.com/cmars/affinity/server"
)

func TestStoreSuite(t *testing.T) { TestingT(t) }

type StoreSuite struct{}

var _ = Suite(&StoreSuite{})

func (ss *StoreSuite) TestMemberDelete(c *C) {
	s := NewTestStore()
	s.AddGroup(&Group{
		Id:     "metasyn",
		Admins: []User{User{"meta", "foo"}},
		Members: []User{
			User{"meta", "bar"},
			User{"meta", "baz"},
			User{"meta", "quux"},
		},
	})

	g, err := s.GetGroup("metasyn")
	c.Assert(err, IsNil)
	c.Assert(g, NotNil)
	c.Assert(g.Id, Equals, "metasyn")

	c.Assert(len(g.Members), Equals, 3)
	err = s.DeleteMember("metasyn", User{"meta", "quux"})
	c.Assert(err, IsNil)
	g, err = s.GetGroup("metasyn")
	c.Assert(len(g.Members), Equals, 2)
}

type TestStore struct {
	Admins  map[string][]User
	Members map[string][]User
}

func NewTestStore() *TestStore {
	return &TestStore{
		Admins:  make(map[string][]User),
		Members: make(map[string][]User),
	}
}

func (s *TestStore) AddGroup(group *Group) error {
	_, has := s.Admins[group.Id]
	if has {
		return fmt.Errorf("already exists")
	}
	s.Admins[group.Id] = group.Admins
	s.Members[group.Id] = group.Members
	return nil
}

func (s *TestStore) GetGroup(groupId string) (*Group, error) {
	admins, has := s.Admins[groupId]
	if !has {
		return nil, NotFound
	}
	group := &Group{Id: groupId}
	for _, admin := range admins {
		group.Admins = append(group.Admins, admin)
	}
	members := s.Members[groupId]
	for _, member := range members {
		group.Members = append(group.Members, member)
	}
	return group, nil
}

func (s *TestStore) DeleteGroup(groupId string) error {
	delete(s.Admins, groupId)
	delete(s.Members, groupId)
	return nil
}

func (s *TestStore) AddMember(groupId string, user User) error {
	members, has := s.Members[groupId]
	if !has {
		return NotFound
	}
	for _, member := range members {
		if member.Equals(user) {
			return nil
		}
	}
	members = append(members, user)
	s.Members[groupId] = members
	return nil
}

func (s *TestStore) DeleteMember(groupId string, user User) error {
	members, has := s.Members[groupId]
	if !has {
		return NotFound
	}
	newMembers := []User{}
	for _, member := range members {
		if !member.Equals(user) {
			newMembers = append(newMembers, member)
		}
	}
	s.Members[groupId] = newMembers
	return nil
}

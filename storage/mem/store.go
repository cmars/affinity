/*
   Affinity - Private groups as a service
   Copyright (C) 2014  Canonical, Ltd.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Library General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package mem

import (
	"github.com/juju/affinity/rbac"
	"github.com/juju/affinity/util"
)

type grant struct {
	principal, role, resource string
}

type grantSet map[grant]bool

type groupMap map[string]util.StringSet

type memStore struct {
	grants grantSet
	groups groupMap
}

func NewStore() rbac.Store {
	return &memStore{
		grants: make(grantSet),
		groups: make(groupMap),
	}
}

func (s *memStore) HasGrant(principal, role, resource string, transitive bool) (bool, error) {
	var search []string
	if transitive {
		groups, err := s.GroupsOf(principal, true)
		if err != nil {
			return false, err
		}
		search = append(search, groups...)
	} else {
		search = append(search, principal)
	}
	for _, p := range search {
		if _, has := s.grants[grant{p, role, resource}]; has {
			return true, nil
		}
	}
	return false, nil
}

func (s *memStore) AddGroup(group string) error {
	if _, has := s.groups[group]; has {
		return nil
	}
	s.groups[group] = make(util.StringSet)
	return nil
}

func (s *memStore) RemoveGroup(group string) error {
	delete(s.groups, group)
	return nil
}

func (s *memStore) AddMember(group, member string) error {
	groups, has := s.groups[group]
	if !has {
		return rbac.ErrNotFound
	}
	groups[member] = true
	return nil
}

func (s *memStore) RemoveMember(group, member string) error {
	groups, has := s.groups[group]
	if !has {
		return rbac.ErrNotFound
	}
	delete(groups, member)
	return nil
}

func (s *memStore) GroupsOf(principal string, transitive bool) ([]string, error) {
	var result []string
	pending := []string{principal}
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		for groupName, members := range s.groups {
			if _, has := members[current]; has {
				result = append(result, groupName)
				if transitive {
					pending = append(pending, groupName)
				}
			}
		}
	}
	return util.UniqueStrings(result), nil
}

func (s *memStore) InsertGrant(principal, role, resource string) error {
	s.grants[grant{principal, role, resource}] = true
	return nil
}

func (s *memStore) RemoveGrant(principal, role, resource string) error {
	delete(s.grants, grant{principal, role, resource})
	return nil
}

func (s *memStore) ResourceGrants(resource string) (principals, roles []string, err error) {
	for grant := range s.grants {
		if grant.resource == resource {
			principals = append(principals, grant.principal)
			roles = append(roles, grant.role)
		}
	}
	return
}

func (s *memStore) PrincipalGrants(principal string, transitive bool) (roles, resources []string, err error) {
	search := make(util.StringSet)
	if transitive {
		var groups []string
		groups, err = s.GroupsOf(principal, true)
		if err != nil {
			return
		}
		search.AddAll(groups...)
	}
	search[principal] = true

	for grant := range s.grants {
		if _, has := search[grant.principal]; has {
			roles = append(roles, grant.role)
			resources = append(resources, grant.resource)
		}
	}
	return
}

func (s *memStore) RoleGrants(principal, resource string, transitive bool) ([]string, error) {
	var roles []string
	for grant := range s.grants {
		if grant.principal == principal && grant.resource == resource {
			roles = append(roles, grant.role)
		}
	}
	return roles, nil
}

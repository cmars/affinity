package affinity_test

import (
	. "launchpad.net/go-affinity"
)

type grant struct {
	principal, role, resource string
}

type grantSet map[grant]bool

type stringSet map[string]bool

type Set map[string]bool

type groupMap map[string]stringSet

type memStore struct {
	grants grantSet
	groups groupMap
}

func NewMemStore() Store {
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
	s.groups[group] = make(stringSet)
	return nil
}

func (s *memStore) RemoveGroup(group string) error {
	delete(s.groups, group)
	return nil
}

func (s *memStore) AddMember(group, member string) error {
	groups, has := s.groups[group]
	if !has {
		return NotFound
	}
	groups[member] = true
	return nil
}

func (s *memStore) RemoveMember(group, member string) error {
	groups, has := s.groups[group]
	if !has {
		return NotFound
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
	return unique(result), nil
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

func unique(items []string) []string {
	var result []string
	u := make(map[string]bool)
	for _, item := range items {
		u[item] = true
	}
	for item := range u {
		result = append(result, item)
	}
	return result
}

func newStringSet(items []string) stringSet {
	result := make(stringSet)
	for _, item := range items {
		result[item] = true
	}
	return result
}

func (ss stringSet) AddAll(items ...string) {
	for _, item := range items {
		ss[item] = true
	}
}

func (s *memStore) PrincipalGrants(principal string, transitive bool) (roles, resources []string, err error) {
	search := make(stringSet)
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

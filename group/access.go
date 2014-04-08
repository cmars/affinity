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

package group

import (
	"fmt"

	"github.com/juju/affinity"
	"github.com/juju/affinity/rbac"
)

// GroupService provides group administration and queries with access controls.
type GroupService struct {
	*rbac.Admin
	AsUser affinity.Principal
	facts  *rbac.GroupFacts
}

// NewGroupService creates a new group service using the given storage, with access
// to operations as the given user.
func NewGroupService(store rbac.FactStore, asUser affinity.Principal) *GroupService {
	return &GroupService{
		Admin:  rbac.NewAdmin(store, GroupRoles),
		AsUser: asUser,
		facts:  rbac.NewGroupFacts(store),
	}
}

// canGroup tests if a user or group has a specific permission on a group.
func (s *GroupService) canGroup(principal affinity.Principal, perm rbac.Permission, group affinity.Principal) error {
	groupRc, err := newGroupResource(group)
	if err != nil {
		return err
	}
	if ok, err := s.Can(principal, perm, groupRc); !ok {
		return fmt.Errorf("%q has no permission to %q on group %q", principal.String(),
			perm.Perm(), group.String())
	} else {
		return err
	}
}

// canService tests if a user or group has a specific permission on this service.
func (s *GroupService) canService(principal affinity.Principal, perm rbac.Permission) error {
	if ok, err := s.Can(principal, perm, serviceResource{}); !ok {
		return fmt.Errorf("%q has no permission to %q on service", principal.String(), perm.Perm())
	} else {
		return err
	}
}

// CheckMember tests if a principal is immediately or transitively a member of a group.
func (s *GroupService) CheckMember(group affinity.Principal, member affinity.Principal) (bool, error) {
	var err error
	if err = s.canGroup(s.AsUser, CheckMemberPerm{}, group); err != nil {
		return false, err
	}
	principal := member.String()
	groups, err := s.facts.Groups(principal)
	if err != nil {
		return false, nil
	}
	for _, groupId := range groups {
		if group.String() == groupId {
			return true, nil
		}
	}
	return false, err
}

// AddGroup defines a new group. The current user is granted the Owner role over the group.
// The current user must be allowed to add groups on this service.
func (s *GroupService) AddGroup(group affinity.Principal) error {
	var err error
	if err = s.canService(s.AsUser, AddGroupPerm{}); err != nil {
		return err
	}
	err = s.facts.AddGroup(group.String())
	if err != nil {
		return err
	}
	groupRc, err := newGroupResource(group)
	if err != nil {
		return err
	}
	return s.Grant(s.AsUser, OwnerRole, groupRc)
}

// RemoveGroup removes an existing group. The current user must own the group.
func (s *GroupService) RemoveGroup(group affinity.Principal) error {
	groupRc, err := newGroupResource(group)
	if err != nil {
		return err
	}
	if err = s.canGroup(s.AsUser, RemoveGroupPerm{}, group); err != nil {
		return err
	}
	// Remove all role grants on the group as a resource
	if err = s.RemoveAll(groupRc); err != nil {
		return err
	}
	// Remove the group
	err = s.facts.RemoveGroup(group.String())
	if err != nil {
		return err
	}
	return nil
}

// AddMember adds a new member to an existing group.
func (s *GroupService) AddMember(group, member affinity.Principal) error {
	var err error
	if err = s.canGroup(s.AsUser, AddMemberPerm{}, group); err != nil {
		return err
	}
	// Add the group membership. Should error if duplicate.
	err = s.facts.AddMember(group.String(), member.String())
	if err != nil {
		return err
	}
	return nil
}

// RemoveMember removes an existing member from a group.
func (s *GroupService) RemoveMember(group, member affinity.Principal) error {
	var err error
	if err = s.canGroup(s.AsUser, RemoveMemberPerm{}, group); err != nil {
		return err
	}
	// Remove the group membership if exists.
	err = s.facts.RemoveMember(group.String(), member.String())
	if err != nil {
		return err
	}
	return nil
}

// GrantOnGroup grants a principal (user or group) role permissions on a group.
// The current user must own the group.
func (s *GroupService) GrantOnGroup(principal affinity.Principal, role rbac.Role, group affinity.Principal) error {
	groupRc, err := newGroupResource(group)
	if err != nil {
		return err
	}
	if err = s.canGroup(s.AsUser, GrantOnGroupPerm{}, group); err != nil {
		return err
	}
	return s.Grant(principal, role, groupRc)
}

// RevokeOnGroup revokes a principal (user or group) role permissions from a group.
// The current user must own the group.
func (s *GroupService) RevokeOnGroup(principal affinity.Principal, role rbac.Role, group affinity.Principal) error {
	groupRc, err := newGroupResource(group)
	if err != nil {
		return err
	}
	if err = s.canGroup(s.AsUser, RevokeOnGroupPerm{}, group); err != nil {
		return err
	}
	return s.Revoke(principal, role, groupRc)
}

func (s *GroupService) GrantOnService(principal affinity.Principal, role rbac.Role) error {
	var err error
	if err = s.canService(s.AsUser, GrantOnServicePerm{}); err != nil {
		return err
	}
	return s.Grant(principal, role, serviceResource{})
}

func (s *GroupService) RevokeOnService(principal affinity.Principal, role rbac.Role) error {
	var err error
	if err = s.canService(s.AsUser, RevokeOnServicePerm{}); err != nil {
		return err
	}
	return s.Revoke(principal, role, serviceResource{})
}

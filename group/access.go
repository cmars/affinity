package group

import (
	"fmt"

	. "launchpad.net/go-affinity"
)

// GroupService provides group administration and queries with access controls.
type GroupService struct {
	*Admin
	AsUser User
}

// NewGroupService creates a new group service using the given storage, with access
// to operations as the given user.
func NewGroupService(store Store, asUser User) *GroupService {
	return &GroupService{NewAdmin(store, GroupRoles), asUser}
}

// canGroup tests if a user or group has a specific permission on a group.
func (s *GroupService) canGroup(principal Principal, perm Permission, groupId string) error {
	if ok, err := s.Can(principal, perm, groupResource(groupId)); !ok {
		return fmt.Errorf("%s has no permission to %s on group %s", principal.String(),
			perm.Name(), groupId)
	} else {
		return err
	}
}

// canService tests if a user or group has a specific permission on this service.
func (s *GroupService) canService(principal Principal, perm Permission) error {
	if ok, err := s.Can(principal, perm, serviceResource{}); !ok {
		return fmt.Errorf("%s has no permission to %s on service", principal.String(), perm.Name())
	} else {
		return err
	}
}

// CheckMember tests if a principal is effectively a member of a group.
func (s *GroupService) CheckMember(groupId string, member Principal) (bool, error) {
	var err error
	if err = s.canGroup(s.AsUser, CheckMemberPerm{}, groupId); err != nil {
		return false, err
	}
	principal := member.String()
	for err == nil {
		if groupId == principal {
			return true, nil
		}
		principal, err = s.Store.ParentOf(principal)
	}
	return false, err
}

// AddGroup defines a new group. The current user is granted the Owner role over the group
// if permitted.
func (s *GroupService) AddGroup(groupId string) error {
	var err error
	if err = s.canService(s.AsUser, AddGroupPerm{}); err != nil {
		return err
	}
	// TODO: test for existing grant on this resource!!!
	return s.Grant(s.AsUser, OwnerRole, groupResource(groupId))
}

// RemoveGroup removes an existing group. The current user must own the group.
func (s *GroupService) RemoveGroup(groupId string) error {
	// TODO: remove all children of this group
	// TODO: revoke all grants to this group
	panic("TODO")
}

// AddMember adds a new member to an existing group.
func (s *GroupService) AddMember(groupId string, principal Principal) error {
	// TODO: add parent, child
	panic("TODO")
}

// RemoveMember removes an existing member from a group.
func (s *GroupService) RemoveMember(groupId string, principal Principal) error {
	// TODO: remove parent, child
	panic("TODO")
}

// GrantOnGroup grants a principal (user or group) role permissions on a group.
// The current user must own the group.
func (s *GroupService) GrantOnGroup(principal Principal, role Role, groupId string) error {
	// TODO: grant role to principal on group
	panic("TODO")
}

// GrantOnGroup revokes a principal (user or group) role permissions from a group.
// The current user must own the group.
func (s *GroupService) RevokeOnGroup(principal Principal, role Role, groupId string) error {
	// TODO: revoke role from principal on group
	panic("TODO")
}

func (s *GroupService) GrantOnService(principal Principal, role Role) error {
	// TODO: grant role to principal on service (add groups)
	panic("TODO")
}

func (s *GroupService) RevokeOnService(principal Principal, role Role) error {
	panic("TODO")
}

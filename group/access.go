package group

import (
	"fmt"

	. "launchpad.net/go-affinity"
)

type GroupService struct {
	*Admin
	AsUser User
}

func NewGroupService(store Store, asUser User) *GroupService {
	return &GroupService{NewAdmin(store, GroupRoles), asUser}
}

func (s *GroupService) canGroup(principal Principal, perm Permission, groupId string) error {
	if ok, err := s.Can(principal, perm, groupResource(groupId)); !ok {
		return fmt.Errorf("%s has no permission to %s on group %s", principal.String(),
			perm.Name(), groupId)
	} else {
		return err
	}
}

func (s *GroupService) canService(principal Principal, perm Permission) error {
	if ok, err := s.Can(principal, perm, serviceResource{}); !ok {
		return fmt.Errorf("%s has no permission to %s on service", principal.String(), perm.Name())
	} else {
		return err
	}
}

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

func (s *GroupService) AddGroup(groupId string) error {
	var err error
	if err = s.canService(s.AsUser, AddGroupPerm{}); err != nil {
		return err
	}
	return s.Grant(s.AsUser, OwnerRole, groupResource(groupId))
}

func (s *GroupService) RemoveGroup(groupId string) error {
	// TODO: remove all children of this group
	// TODO: revoke all grants to this group
	panic("TODO")
}

func (s *GroupService) AddMember(groupId string, principal Principal) error {
	// TODO: add parent, child
	panic("TODO")
}

func (s *GroupService) RemoveMember(groupId string, principal Principal) error {
	// TODO: remove parent, child
	panic("TODO")
}

func (s *GroupService) GrantOnGroup(principal Principal, role Role, groupId string) error {
	// TODO: grant role to principal on group
	panic("TODO")
}

func (s *GroupService) RevokeOnGroup(principal Principal, role Role, groupId string) error {
	// TODO: revoke role from principal on group
	panic("TODO")
}

func (s *GroupService) GrantOnService(principal Principal, role Role) error {
	// TODO: grant role to principal on service (add groups)
	panic("TODO")
}

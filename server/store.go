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

package server

import (
	"fmt"

	. "launchpad.net/go-affinity"
)

var NotFound error = fmt.Errorf("Not found")

type Store interface {
	// CreateGroup creates a new group.
	CreateGroup(group *Group) error
	// GetGroup fetches a group by its unique id.
	GetGroup(groupId string) (*Group, error)
	// DeleteGroup deletes the group from storage by its unique id.
	DeleteGroup(groupId string) error

	// AddMember adds a user to an existing group.
	AddMember(groupId string, user User) error
	// DeleteMember removes a user from an existing group.
	DeleteMember(groupId string, user User) error

	// AddAdmin adds an administrative user to an existing group.
	AddAdmin(groupId string, user User) error
	// DeleteAdmin removes an administrative user from an existing group.
	DeleteAdmin(groupId string, user User) error

	// GetPermission fetches a permission by its unique id.
	GetPermission(permId string) (*Permission, error)

	// GetRole fetches a role by its unique id.
	GetRole(roleId string) (*Role, error)

	// AddPermission adds a permission to an existing role.
	AddPermission(permId string, roleId string) error
	// RemovePermission removes a permission from an existing role.
	RemovePermission(permId string, roleId string) error

	// GrantRole grants all the privileges of a given role to a user on a resource.
	GrantRole(roleId string, user User, resourceUri string) error
	// RevokeRole removes the privileges of a given role from a user on a resource.
	RevokeRole(roleId string, user User, resourceUri string) error
	// RevokeUser removes the privileges of a given role from a user for all resources.
	RevokeUser(roleId string, user User) error

	// GetPermissions gets the effective permissions granted to a user on a given resource.
	GetPermissions(user User, resourceUri string) ([]*Permission, error)
}

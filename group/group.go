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
	. "github.com/juju/affinity/rbac"
)

// AffinityGroupsUri defines a namespace for roles affecting the entire
// group database -- such as adding and removing groups.
const AffinityGroupsUri = "affinity-group-service:"

// AddGroupPerm is permission on this service to add a group.
type AddGroupPerm struct{}

func (p AddGroupPerm) Perm() string { return "add-group" }

// RemoveGroupPerm is permission to remove a group.
type RemoveGroupPerm struct{}

func (p RemoveGroupPerm) Perm() string { return "remove-group" }

// AddMemberPerm is permission to add a member to a group.
type AddMemberPerm struct{}

func (p AddMemberPerm) Perm() string { return "add-member" }

// RemoveMemberPerm is permission to remove a member from a group.
type RemoveMemberPerm struct{}

func (p RemoveMemberPerm) Perm() string { return "remove-member" }

// CheckMemberPerm is permission to check membership on a group.
type CheckMemberPerm struct{}

func (p CheckMemberPerm) Perm() string { return "check-member" }

// GrantOnGroupPerm is permission to grant permissions on a group.
type GrantOnGroupPerm struct{}

func (p GrantOnGroupPerm) Perm() string { return "grant-on-group" }

// RevokeOnGroupPerm is permission to revoke permissions on a group.
type RevokeOnGroupPerm struct{}

func (p RevokeOnGroupPerm) Perm() string { return "revoke-on-group" }

// GrantOnServicePerm is permission to grant permissions on this service.
type GrantOnServicePerm struct{}

func (p GrantOnServicePerm) Perm() string { return "grant-on-service" }

// RevokeOnServicePerm is permission to revoke permissions on this service.
type RevokeOnServicePerm struct{}

func (p RevokeOnServicePerm) Perm() string { return "revoke-on-service" }

var creatorCapabilities PermissionMap = NewPermissionMap(
	AddGroupPerm{},
)

var ownerCapabilities PermissionMap = NewPermissionMap(
	GrantOnGroupPerm{}, RevokeOnGroupPerm{},
	RemoveGroupPerm{},
	AddMemberPerm{}, RemoveMemberPerm{},
	CheckMemberPerm{},
)

var adminCapabilities PermissionMap = NewPermissionMap(
	AddMemberPerm{}, RemoveMemberPerm{},
	CheckMemberPerm{},
)

var observerCapabilities PermissionMap = NewPermissionMap(
	CheckMemberPerm{},
)

var serviceCapabilities PermissionMap = NewPermissionMap(
	GrantOnServicePerm{}, RevokeOnServicePerm{}, AddGroupPerm{},
)

type groupRole struct {
	name         string
	capabilities PermissionMap
}

func (gr *groupRole) Capabilities() PermissionMap {
	return gr.capabilities
}

func (gr *groupRole) Role() string {
	return gr.name
}

func (gr *groupRole) Can(do Permission) bool {
	_, has := gr.capabilities[do.Perm()]
	return has
}

// ServiceRole is allowed to manage the service
var ServiceRole *groupRole = &groupRole{"service", serviceCapabilities}

// CreatorRole is allowed to create groups
var CreatorRole *groupRole = &groupRole{"creator", creatorCapabilities}

// OwnerRole is allowed all group-level operations on a group
var OwnerRole *groupRole = &groupRole{"owner", ownerCapabilities}

// AdminRole is allowed to add, remove and check membership.
var AdminRole *groupRole = &groupRole{"admin", adminCapabilities}

// ObserverRole is allow to check membership of a group.
var ObserverRole *groupRole = &groupRole{"observer", observerCapabilities}

type groupResource string

func (_ groupResource) Capabilities() PermissionMap { return ownerCapabilities }

func (gr groupResource) URI() string { return string(gr) }

func (gr groupResource) ParentOf() Resource { return ServiceResource }

type serviceResource struct{}

func (_ serviceResource) Capabilities() PermissionMap {
	return serviceCapabilities
}

func (_ serviceResource) URI() string { return AffinityGroupsUri }

func (_ serviceResource) ParentOf() Resource { return nil }

var ServiceResource Resource = serviceResource{}

var GroupRoles RoleMap = NewRoleMap(ServiceRole, CreatorRole, OwnerRole, AdminRole, ObserverRole)

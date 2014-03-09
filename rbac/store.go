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

package rbac

// Store defines the backend storage API for the affinitya role-based
// access control system. The interface is designed to be low-level enough
// for NoSQL databases such as document or key-value stores.
type Store interface {
	// HasGrant tests if the principal is assigned to a role for operating on the resource.
	HasGrant(principal, role, resource string, transitive bool) (bool, error)
	// AddGroup adds a group.
	AddGroup(group string) error
	// RemoveGroup removes a group and all its members
	RemoveGroup(group string) error
	// AddMember adds a group-member relationship between principal identifiers.
	AddMember(group, member string) error
	// RemoveMember removes a group-member relationship between principal identifiers.
	RemoveMember(group, member string) error
	// GroupsOf returns the groups to which the given principal belongs to.
	// Note that a principal can be a member of multiple groups. Either immediate
	// or complete, transitive group memberships can be obtained.
	GroupsOf(principal string, transitive bool) ([]string, error)
	// InsertGrant adds a principal-role-resource statement of fact that represents
	// a role assignment.
	InsertGrant(principal, role, resource string) error
	// RemoveGrant removes the principal-role-resource representation of a role assignment.
	RemoveGrant(principal, role, resource string) error
	// ResourceGrants returns index-matched slices containing all the principal-role grants
	// on the given resource.
	ResourceGrants(resource string) (principals, roles []string, err error)
	// PrincipalGrants returns index-matched slices containing the immediate
	// or complete, transitive role-resource pairs that apply to the principal.
	PrincipalGrants(principal string, transitive bool) (roles, resources []string, err error)
	// RoleGrants returns a slice of the roles granted to a principal on a resource.
	RoleGrants(principal, resource string, transitive bool) ([]string, error)
}

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

package affinity

// Store defines the backend storage API for the affinitya role-based
// access control system. The interface is designed to be low-level enough
// for NoSQL databases such as document or key-value stores.
type Store interface {
	// HasGrant tests if the principal is assigned to a role for operating on the resource.
	// To test if the grant is conferred to the principal by its parents,
	// use effective=true.
	HasGrant(principal, role, resource string, effective bool) (bool, error)
	// AddChild adds a parent-child relationship between principal identifiers.
	// This is used to store groups.
	AddChild(parent, child string) error
	// ParentOf returns the parent of the given identifier, if one was previously
	// declared. If not, returns NotFound.
	ParentOf(principal string) (string, error)
	// InsertGrant adds a principal-role-resource statement of fact that represents
	// a role assignment.
	InsertGrant(principal, role, resource string) error
	// RemoveGrant removes the principal-role-resource representation of a role assignment.
	RemoveGrant(principal, role, resource string) error
	// ResourceGrants returns index-matched slices containing all the principal-role grants
	// on the given resource.
	ResourceGrants(resource string) (principals, roles []string, err error)
	// PrincipalGrants returns index-matched slices containing all the effective
	// role-resource pairs. For all grants conferred by parents, use effective=true.
	PrincipalGrants(principal string, effective bool) (roles, resources []string, err error)
	// RoleGrants returns a slice of all the effective roles granted to a principal on a resource.
	RoleGrants(principal, resource string) ([]string, error)
}

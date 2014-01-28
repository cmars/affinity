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

import (
	"fmt"
)

var ErrNotFound error = fmt.Errorf("Not found")

var ErrAlreadyGranted error = fmt.Errorf("Already granted")

// Permission represents a granular capability that can be performed on a resource.
type Permission interface {
	Name() string
}

type basicPerm struct {
	name string
}

func (bp *basicPerm) Name() string { return bp.name }

// NewPermission defines a new permission identified by a well-known, unique name.
func NewPermission(name string) Permission { return &basicPerm{name} }

// Resource represents the object of access controls.
type Resource interface {
	// Capabilities returns all the possible permissions that are defined for this type of resource.
	Capabilities() PermissionMap
	// URI returns the uniform identifier for this resource.
	URI() string
}

type basicResource struct {
	uri          string
	capabilities PermissionMap
}

func (br *basicResource) Capabilities() PermissionMap { return br.capabilities }

func (br *basicResource) URI() string { return br.uri }

func NewResource(uri string, capabilities ...Permission) Resource {
	return &basicResource{uri, NewPermissionMap(capabilities...)}
}

// Role represents a set of permissions (capabilities, actions) to operate on a resource.
type Role interface {
	// Permissions that have been relegated to this role.
	Capabilities() PermissionMap
	// Name returns the locally distinguished name for this role.
	Name() string
	// Can tests if the role allows the given permission.
	Can(p Permission) bool
}

type basicRole struct {
	name  string
	perms PermissionMap
}

func (br *basicRole) Name() string {
	return br.name
}

func (br *basicRole) Capabilities() PermissionMap {
	return br.perms
}

func (br *basicRole) Can(p Permission) bool {
	_, has := br.perms[p.Name()]
	return has
}

// NewRole defines a new role identified by a well-known, unique name with access to
// the specified permissions.
func NewRole(name string, permissions ...Permission) Role {
	return &basicRole{name, NewPermissionMap(permissions...)}
}

// Grant represents a statement of fact that a principal (user, group, identity)
// can act in a given role (perform actions on) with regard to some resource object.
type Grant interface {
	// Principal is the subject granted permissions.
	Principal() Principal
	// Role is the predicated bundle of permissions.
	Role() Role
	// Resource is the object of said permissions.
	Resource() Resource
}

type RoleMap map[string]Role

func NewRoleMap(roles ...Role) RoleMap {
	roleMap := make(RoleMap)
	for _, role := range roles {
		roleMap[role.Name()] = role
	}
	return roleMap
}

type PermissionMap map[string]Permission

func NewPermissionMap(permissions ...Permission) PermissionMap {
	permissionMap := make(PermissionMap)
	for _, permission := range permissions {
		permissionMap[permission.Name()] = permission
	}
	return permissionMap
}

// Access provides query capabilities over the role-based
// access control system.
type Access struct {
	Store Store
	Roles RoleMap
}

func NewAccess(store Store, roles RoleMap) *Access {
	return &Access{store, roles}
}

// Can tests if the princial has a permission on a given resource.
func (s *Access) Can(pr Principal, pm Permission, r Resource) (bool, error) {
	roleGrants, err := s.Store.RoleGrants(pr.String(), r.URI(), true)
	if err != nil {
		return false, err
	}
	// Add scheme wildcard grants
	if user, is := pr.(User); is && !user.Wildcard() {
		wildcardGrants, err := s.Store.RoleGrants(
			User{Identity{user.Scheme, AnyId}}.String(), r.URI(), true)
		if err != nil {
			return false, err
		}
		roleGrants = append(roleGrants, wildcardGrants...)
	}
	for _, roleName := range roleGrants {
		role, has := s.Roles[roleName]
		if !has {
			return false, fmt.Errorf("Role %s not supported", roleName)
		}
		if role.Can(pm) {
			return true, nil
		}
	}
	return false, nil
}

// Admin provides administrative capabilities over the role-based
// access control system.
type Admin struct {
	*Access
}

func NewAdmin(store Store, roles RoleMap) *Admin {
	return &Admin{NewAccess(store, roles)}
}

// Grant allows a principal permissions to act upon a given resource.
func (s *Admin) Grant(pr Principal, ro Role, rs Resource) error {
	can, err := s.Can(pr, ro, rs)
	if err != nil {
		return err
	}
	if can {
		return fmt.Errorf("Role %s already effectively granted to %s on %s",
			ro.Name(), pr.String(), rs.URI())
	}
	return s.Store.InsertGrant(pr.String(), ro.Name(), rs.URI())
}

// Revoke removes a prior grant of permissions to a principal on a resource.
func (s *Admin) Revoke(pr Principal, ro Role, rs Resource) error {
	return s.Store.RemoveGrant(pr.String(), ro.Name(), rs.URI())
}

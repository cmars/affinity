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

package testing

import (
	. "launchpad.net/gocheck"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/rbac"
)

type RbacTests struct {
	*StoreTests
	Access *rbac.Access
	Admin  *rbac.Admin
}

type RbacSuite struct {
	*RbacTests
}

type UseThingPerm struct{}

func (p UseThingPerm) Perm() string { return "use-thing" }

type EmptyBucketPerm struct{}

func (p EmptyBucketPerm) Perm() string { return "empty-bucket" }

type FillBucketPerm struct{}

func (p FillBucketPerm) Perm() string { return "fill-bucket" }

var FacilitiesCapabilities rbac.PermissionMap = rbac.NewPermissionMap(EmptyBucketPerm{}, FillBucketPerm{}, UseThingPerm{})

type ControlShipPerm struct{}

func (p ControlShipPerm) Perm() string { return "control-ship" }

type BoardShipPerm struct{}

func (p BoardShipPerm) Perm() string { return "board-ship" }

var SpacecraftCapabilities rbac.PermissionMap = rbac.NewPermissionMap(ControlShipPerm{}, BoardShipPerm{})

type PerformSurgeryPerm struct{}

func (p PerformSurgeryPerm) Perm() string { return "perform-surgery" }

var MedicalCapabilities rbac.PermissionMap = rbac.NewPermissionMap(PerformSurgeryPerm{})

type FilePaperworkPerm struct{}

func (p FilePaperworkPerm) Perm() string { return "file-paperwork" }

var BureaucraticCapabilities rbac.PermissionMap = rbac.NewPermissionMap(FilePaperworkPerm{})

type characterRole struct {
	name         string
	capabilities rbac.PermissionMap
}

func (r *characterRole) Capabilities() rbac.PermissionMap {
	return r.capabilities
}

func (r *characterRole) Role() string {
	return r.name
}

func (r *characterRole) Can(do rbac.Permission) bool {
	_, has := r.capabilities[do.Perm()]
	return has
}

var UserRole *characterRole = &characterRole{"user", rbac.NewPermissionMap(
	UseThingPerm{},
)}

var JanitorRole *characterRole = &characterRole{"janitor", rbac.NewPermissionMap(
	EmptyBucketPerm{}, FillBucketPerm{},
)}

var PilotRole *characterRole = &characterRole{"pilot", rbac.NewPermissionMap(
	BoardShipPerm{}, ControlShipPerm{},
)}

var PassengerRole *characterRole = &characterRole{"passenger", rbac.NewPermissionMap(
	BoardShipPerm{},
)}

var BureaucratRole *characterRole = &characterRole{"bureaucrat", rbac.NewPermissionMap(
	FilePaperworkPerm{},
)}

var DoctorRole *characterRole = &characterRole{"doctor", rbac.NewPermissionMap(
	PerformSurgeryPerm{},
)}

var FuturamaRoles rbac.RoleMap = rbac.NewRoleMap(
	JanitorRole,
	PilotRole,
	PassengerRole,
	BureaucratRole,
	DoctorRole,
	UserRole,
)

type facilitiesResource struct {
	parent *facilitiesResource
	name   string
}

func (_ facilitiesResource) Capabilities() rbac.PermissionMap { return FacilitiesCapabilities }
func (r facilitiesResource) URI() string                      { return r.name }
func (r facilitiesResource) ParentOf() rbac.Resource {
	if r.parent == nil {
		return nil
	}
	return *r.parent
}

type spacecraftResource string

func (_ spacecraftResource) Capabilities() rbac.PermissionMap { return SpacecraftCapabilities }
func (r spacecraftResource) URI() string                      { return string(r) }
func (_ spacecraftResource) ParentOf() rbac.Resource          { return nil }

type medicalResource string

func (_ medicalResource) Capabilities() rbac.PermissionMap { return MedicalCapabilities }
func (r medicalResource) URI() string                      { return string(r) }
func (_ medicalResource) ParentOf() rbac.Resource          { return nil }

type bureaucraticResource string

func (_ bureaucraticResource) Capabilities() rbac.PermissionMap { return BureaucraticCapabilities }
func (r bureaucraticResource) URI() string                      { return string(r) }
func (_ bureaucraticResource) ParentOf() rbac.Resource          { return nil }

func NewRbacSuite(s rbac.Store) *RbacSuite {
	return &RbacSuite{
		&RbacTests{&StoreTests{s},
			rbac.NewAccess(s, FuturamaRoles),
			rbac.NewAdmin(s, FuturamaRoles),
		},
	}
}

func (s *RbacSuite) SetUp(c *C) {
	building := facilitiesResource{name: "facilities:building"}
	for _, grant := range futuramaGrants {
		var rc rbac.Resource
		switch grant.resource {
		case "facilities:bucket":
			rc = facilitiesResource{name: grant.resource, parent: &building}
		case "bureaucracy:forms":
			rc = bureaucraticResource(grant.resource)
		case "planet-express:crew":
			rc = bureaucraticResource(grant.resource)
		case "spacecraft:ship":
			rc = spacecraftResource(grant.resource)
		default:
			c.Fail()
		}
		u := MustParseUser(grant.principal)
		role, has := FuturamaRoles[grant.role]
		c.Assert(has, Equals, true)
		err := s.Admin.Grant(u, role, rc)
		c.Assert(err, IsNil)
	}
}

func (s *RbacSuite) TestScruffyAcls(c *C) {
	var can bool
	// Scruffy should be able to empty the bucket
	can, _ = s.Access.Can(
		MustParseUser("test:scruffy"),
		EmptyBucketPerm{},
		facilitiesResource{name: "facilities:bucket"})
	c.Assert(can, Equals, true)
	// Scruffy should not be able to empty some other bucket we haven't granted the role on
	can, _ = s.Access.Can(
		MustParseUser("test:scruffy"),
		EmptyBucketPerm{},
		facilitiesResource{name: "walrus:bucket"})
	c.Assert(can, Equals, false)
	// Scruffy should not be able to empty the ship like it was a bucket
	can, _ = s.Access.Can(
		MustParseUser("test:scruffy"),
		EmptyBucketPerm{},
		facilitiesResource{name: "spacecraft:ship"})
	c.Assert(can, Equals, false)
	// Scruffy should not be able to board the ship. Sorry Scruffy, it's canon.
	can, _ = s.Access.Can(
		MustParseUser("test:scruffy"),
		BoardShipPerm{},
		spacecraftResource("spacecraft:ship"))
	c.Assert(can, Equals, false)
	// Crew member should not be able to wield the mighty bucket
	can, _ = s.Access.Can(
		MustParseUser("test:fry"),
		FillBucketPerm{},
		facilitiesResource{name: "facilities:bucket"})
}

func (s *RbacSuite) TestSpacecraftAcls(c *C) {
	var can bool
	// Leela should be able to fly the ship.
	can, _ = s.Access.Can(
		MustParseUser("test:leela"),
		ControlShipPerm{},
		spacecraftResource("spacecraft:ship"))
	c.Assert(can, Equals, true)
	// Leela should be able to board the ship.
	can, _ = s.Access.Can(
		MustParseUser("test:leela"),
		BoardShipPerm{},
		spacecraftResource("spacecraft:ship"))
	c.Assert(can, Equals, true)
	// Fry should be able to fly the ship.
	can, _ = s.Access.Can(
		MustParseUser("test:fry"),
		ControlShipPerm{},
		spacecraftResource("spacecraft:ship"))
	c.Assert(can, Equals, false)
	// Fry should be able to board the ship.
	can, _ = s.Access.Can(
		MustParseUser("test:fry"),
		BoardShipPerm{},
		spacecraftResource("spacecraft:ship"))
	c.Assert(can, Equals, true)
}

func (s *RbacSuite) TestResourceParentGrant(c *C) {
	building := facilitiesResource{name: "planet-express-hq"}
	vendingMachine := facilitiesResource{name: "vending-machine", parent: &building}
	bender := MustParseUser("test:bender")
	s.Admin.Grant(bender, UserRole, building)

	can, err := s.Access.Can(bender, UseThingPerm{}, building)
	c.Assert(err, IsNil)
	c.Assert(can, Equals, true)

	can, err = s.Access.Can(bender, UseThingPerm{}, vendingMachine)
	c.Assert(err, IsNil)
	c.Assert(can, Equals, true)
}

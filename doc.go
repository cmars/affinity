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

/*
affinity supports user identity, user groups, and role-based access
control on resources. Identity and RBAC features are used by working
with several key interfaces worthy of a proper definition and introduction.

Principal

A Principal is a singular User or a corporate Group (a collection of users or subgroups)
which can be granted a Role over a Resource.

User

Users are unique individual accounts which can provide a proof of identity. A user is identified
by a Scheme and an Id string. The Id string must be unique within the scope of the Scheme.

A User can be a member of a Group. A User also can be treated as a Principal. The canonical
string representation of a user identity in affinity is "SchemeName:UserId".

Scheme

A Scheme provides two important functions in affinity:

1. Authenticating a user and generating a proof of identity ownership.

2. Validating that a proof of identity belongs to a given User.

These functions are intended to be adaptable to OAuth, OpenID, SASL and other token-based authentication mechanisms. The Ubuntu Single-Sign On (SSO) provider is a reference example.

Schemes are registered to unique namespaces. This namespace comprises the "SchemeName" component of a canonical User string representation.

Group

A group is a collection of Users or sub-Groups with a unique name. Groups should be defined by a common association, rather than by capability you want the members to have with a resource.

In other words, don't group users to define permissions on resources. Grant common, reusable permissions on resources to users and groups.

It is worth mentioning that some Schemes might support their own concept of user groups. For example, a Launchpad Scheme could access team membership, and a Github Scheme could access Organization membership. Proxying these external groups in Affinity may be supported in future releases.

Permission

[TBD]

Role

[TBD]

GroupService

[TBD]

HTTP API

[TBD]

Examples

I might want to create a group of airline pilots for each airline, and grant permission to "fly-plane" to each pilot group on different airplanes. United pilots can fly United planes, but not JetBlue, or a private jet.

However, the permission of "fly-plane", and the other permissions that go along with the "pilot" role, should be reusable across all these groups of pilots. The pilots are grouped according to their employer, a common association distinct from their role.

*/
package affinity

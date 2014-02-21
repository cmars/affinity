/*
   Affinity - Grouping and role-based access controls for authenticated identities.
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

/*
Affinity provides user grouping and role-based access controls (RBAC) for any identity provider
that defines a small set of authentication primitives.

The examples documented here illustrate basic API usage with a very simple hypothetical message board.

For a more complete example, reference the unit tests, and the source files in package github.com/juju/affinity/group package, where Affinity uses its own RBAC to control access to user-group administration.

github.com/juju/affinity/server exposes an HTTP API over the group service. The command-line interface in cmd/ is a utility to launch the service and connect to it, using Ubuntu SSO as an identity provider.

Use the following types for working with identity and RBAC in Affinity.

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

Permissions are fine-grained capabilities or actions which take place in an application. Affinity provides a means to look up whether a given principal has a permission to act on a certain resource. Each permission is given a name identifier unique to the application capability it represents.

Let your application define your permissions. For example, if you were writing a filesystem, you might have permissions defined like: read-file, execute-file, write-file, read-directory, write-directory, etc.

Role

Roles are a higher-level definition of capabilities. Essentially a Role is a bundle of permissions given a name. Roles should be defined by the "types of access" you wish to grant users and groups on your application's resources.

For example, someone in a Pilot role should have permissions like 'board', 'enter-cabin', 'move-cockpit-controls' on an "airplane" resource. A Passenger role should be able to 'board', but not 'enter-cabin' or 'move-cockpit-controls'.

Resource

A resource is the object to which access is granted. In Affinity, a Resource is declared by a URI, which will have meaning to the application implementating RBAC.

Resources also declare the full set of permissions they support. That way, you can't make absurd role grants that don't make sense for the resource object of the grant.

Resources do not currently support the concept of hierarchy in Affinity -- they are all flat, and in essence just canonical names to be matched in an access control query.

Store

Affinity stores user groupings and role grants in persistent storage. The Store interface defines lower-level primitives which are implemented for different providers, such as MongoDB, in-memory, or others.

Access

Use Access to connect to storage and check access permissions for a given user/group on a resource.

Admin

Admin extends Access with the capability to grant and revoke user or group roles on resources. Role grants in Affinity are "positive" and additive in nature. Granting a role will cause a permission lookup for the user/group on a resource to match if any granted role contains that permission.

Revoking a role will remove this relationship, so that the lookup no longer matches and access is denied.

It is important to note that when it comes to role grants on groups, there is no way to revoke a role's transitive permissions from a group member. All members of the group will receive the role permission, or none of them will.

*/
package affinity

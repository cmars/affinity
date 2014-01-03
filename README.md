# Affinity Service API

## Summary
Affinity provides private groups as-a-service. Groups can be declared by any authenticated user. Users are authenticated and identified according to a supported scheme, which is explained below. When a user declares a new group, the user becomes an administrator of the group automatically.

Group membership is not public information. An authenticated user can test if they are a member of a group, but that is all. Only administrators of a group can list the other members.

Unauthenticated or improperly users cannot determine the existence of a group or user membership by poking at names. Affinity will 404 in such cases.

## Usage
Affinity isn't too interesting by itself, but it could be used to define groups in a distributed manner for other applications. These applications would themselves be members of a group with permission to check membership of others (read-only admin).

## Schemes
Schemes are namespaces under which users can be uniquely identified and authenticated.

### Currently planned

#### usso:
Ubuntu One Single-Sign On accounts. OAuth, basically.

#### affinity:
Not a user, but a sub-group existing locally on the same affinity service. Allows expression of nested groups.

### Under consideration/experimental/could be joking

#### launchpad:
Aside from being another OAuth provider, LP groups could be delegated as a pass-through to Launchpad teams.

#### github:
Aside from being another OAuth provider, Github groups could be delegated as pass-through to Github orgs.

#### google:
#### facebook:
#### twitter:
Some other OAuth providers I have heard of. Pull requests welcome!

#### PGP & SSH public key fingerprints
Auth as proof-of-private key ownership, basically.

For PGP, it would probably be the public key fingerprint (with algorithm and key length).

For SSH, it would be user@host:port and a public key fingerprint.

In both cases, the client could sign a server-generated token "proof" with the private key.

#### ldap URI
Groups could be delegated as a pass-through to LDAP/AD groups.

#### affinity@{URI}:
Federated group hierarchies, affinity groups consisting of affinity groups on other servers.

#### persona:
An affinity: group that defines an individual persona with multiple online identities.

# API

## Common Header Fields

### Authorization
Contains a token which attests the user’s identity according to the given scheme. The token shall contain a scheme name identifying the namespace and method used to verify the authorization token object.

## /{group}

### PUT
Creates the group name if it does not exist. Error if it does. Authenticated user becomes first member & admin of new group.

### DELETE
Delete the group if it does exist. Error if it does not, or authenticated user does not have necessary permissions.

### GET
Get group metadata, filtered by membership of authenticated user. Error if not member.

## /{group}/{scheme:user}

### PUT
Adds the user to the group if authenticated as admin, otherwise error.

### DELETE
Delete the user from the group if authenticated as group admin, otherwise error.

### GET
Get positive confirmation of the user’s membership information in group. 404 if not a member. 401 if not authenticated to know such things.

# Example

	GET /JAMs/usso:simon.moon@example.com

This would check an Ubuntu SSO user simon.moon@example.com for membership in the JAMs group. The request can only be made by Simon Moon himself or an admin of the JAMs group.

	DELETE /JAMs/usso:simon.moon@example.com

This would remove the user from the JAMs, but only an admin can kick out the JAMs.


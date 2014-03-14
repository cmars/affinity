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

package mongo

import (
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"

	"github.com/juju/affinity/rbac"
	"github.com/juju/affinity/util"
)

type grant struct {
	Principal, Role, Resource string
}

type groupMember struct {
	Group, Member string
}

type MongoStore struct {
	*mgo.Session
	db      *mgo.Database
	grants  *mgo.Collection
	groups  *mgo.Collection
	members *mgo.Collection
}

func grantError(err error) error {
	if mgo.IsDup(err) {
		return rbac.ErrAlreadyGranted
	} else if err == mgo.ErrNotFound {
		return rbac.ErrNotFound
	}
	return err
}

func DialMongoStore(url string, dbname, dbuser, dbpass string) (*MongoStore, error) {
	session, err := mgo.Dial(url)
	if err != nil {
		return nil, err
	}
	return NewMongoStore(session, dbname, dbuser, dbpass)
}

var indexes map[string]mgo.Index = map[string]mgo.Index{
	"grants": mgo.Index{
		Key:    []string{"principal", "role", "resource"},
		Unique: true,
	},
	"groups": mgo.Index{
		Key:    []string{"name"},
		Unique: true,
	},
	"members": mgo.Index{
		Key:    []string{"group", "member"},
		Unique: true,
	},
}

func NewMongoStore(session *mgo.Session, dbname, dbuser, dbpass string) (*MongoStore, error) {
	store := &MongoStore{Session: session}
	store.db = store.DB(dbname)
	if dbuser != "" {
		err := store.db.Login(dbuser, dbpass)
		if err != nil {
			return nil, err
		}
	}
	store.grants = store.db.C("grants")
	store.groups = store.db.C("groups")
	store.members = store.db.C("members")

	for name, index := range indexes {
		err := store.db.C(name).EnsureIndex(index)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

func (s *MongoStore) HasGrant(principal, role, resource string, transitive bool) (bool, error) {
	var n int
	var err error
	var search []string
	if transitive {
		search, err = s.GroupsOf(principal, transitive)
		if err != nil {
			return false, err
		}
	}
	search = append(search, principal)
	n, err = s.grants.Find(bson.M{
		"principal": bson.M{"$in": search},
		"role":      role,
		"resource":  resource,
	}).Count()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	return false, nil
}

func (s *MongoStore) AddGroup(group string) error {
	return s.groups.Insert(bson.M{"name": group})
}

func (s *MongoStore) RemoveGroup(group string) error {
	err := s.groups.Remove(bson.M{"name": group})
	if err != nil {
		return err
	}
	_, err = s.members.RemoveAll(bson.M{"group": group})
	return err
}

func (s *MongoStore) AddMember(group, member string) error {
	return s.members.Insert(bson.M{"group": group, "member": member})
}

func (s *MongoStore) RemoveMember(group, member string) error {
	return s.members.Remove(bson.M{"group": group, "member": member})
}

func (s *MongoStore) GroupsOf(principal string, transitive bool) ([]string, error) {
	var result []string
	unique := make(map[string]bool) // used to make result unique
	pending := []string{principal}
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		var groupMembers []groupMember
		err := s.members.Find(bson.M{"member": current}).All(&groupMembers)
		if err == mgo.ErrNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		var groups []string
		for _, gm := range groupMembers {
			if _, has := unique[gm.Group]; !has {
				groups = append(groups, gm.Group)
				unique[gm.Group] = true
			}
		}
		result = append(result, groups...)
		if transitive {
			pending = append(pending, groups...)
		}
	}
	return util.UniqueStrings(result), nil
}

func (s *MongoStore) InsertGrant(principal, role, resource string) error {
	err := s.grants.Insert(bson.M{
		"principal": principal,
		"role":      role,
		"resource":  resource,
	})
	return grantError(err)
}

func (s *MongoStore) RemoveGrant(principal, role, resource string) error {
	err := s.grants.Remove(bson.M{
		"principal": principal,
		"role":      role,
		"resource":  resource,
	})
	return grantError(err)
}

func (s *MongoStore) ResourceGrants(resource string) (principals, roles []string, err error) {
	var grants []grant
	err = s.grants.Find(bson.M{"resource": resource}).All(&grants)
	if err != nil {
		return
	}
	for i := range grants {
		principals = append(principals, grants[i].Principal)
		roles = append(roles, grants[i].Role)
	}
	return
}

func (s *MongoStore) PrincipalGrants(principal string, transitive bool) (roles, resources []string, err error) {
	var grants []grant
	var q *mgo.Query
	if transitive {
		groups, err := s.GroupsOf(principal, transitive)
		if err != nil {
			return nil, nil, err
		}
		groups = append(groups, principal)
		q = s.grants.Find(bson.M{"principal": bson.M{"$in": groups}})
	} else {
		q = s.grants.Find(bson.M{"principal": principal})
	}
	err = q.All(&grants)
	if err != nil {
		return nil, nil, err
	}
	for i := range grants {
		roles = append(roles, grants[i].Role)
		resources = append(resources, grants[i].Resource)
	}
	return roles, resources, nil
}

func (s *MongoStore) RoleGrants(principal, resource string, transitive bool) (roles []string, err error) {
	var grants []grant
	var q *mgo.Query
	if transitive {
		groups, err := s.GroupsOf(principal, transitive)
		if err != nil {
			return nil, err
		}
		groups = append(groups, principal)
		q = s.grants.Find(bson.M{"resource": resource, "principal": bson.M{"$in": groups}})
	} else {
		q = s.grants.Find(bson.M{"resource": resource, "principal": principal})
	}
	err = q.All(&grants)
	for i := range grants {
		roles = append(roles, grants[i].Role)
	}
	return roles, err
}

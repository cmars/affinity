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

package mongo

import (
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"

	"launchpad.net/go-affinity"
)

type grant struct {
	principal, role, resource string
}

type parentChild struct {
	parent, child string
}

type MongoStore struct {
	*mgo.Session
	db      *mgo.Database
	grants  *mgo.Collection
	parents *mgo.Collection
}

func DialMongoStore(url string, dbname string) (*MongoStore, error) {
	session, err := mgo.Dial(url)
	if err != nil {
		return nil, err
	}
	return NewMongoStore(session, dbname)
}

func NewMongoStore(session *mgo.Session, dbname string) (*MongoStore, error) {
	store := &MongoStore{Session: session}
	store.db = store.DB(dbname)
	store.grants = store.db.C("grants")
	store.parents = store.db.C("parents")

	err := store.grants.EnsureIndex(mgo.Index{
		Key:    []string{"principal", "role", "resource"},
		Unique: true,
	})
	if err != nil {
		return nil, err
	}
	err = store.parents.EnsureIndex(mgo.Index{
		Key:    []string{"parent", "child"},
		Unique: true,
	})
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (s *MongoStore) HasGrant(principal, role, resource string, effective bool) (bool, error) {
	var n int
	var err error
	for err == nil && effective {
		n, err = s.grants.Find(bson.M{
			"principal": principal,
			"role":      role,
			"resource":  resource,
		}).Count()
		if err != nil {
			return false, err
		}
		if n > 0 {
			return true, err
		}
		principal, err = s.ParentOf(principal)
	}
	return false, err
}

func (s *MongoStore) AddChild(parent, child string) error {
	return s.parents.Insert(bson.M{"parent": parent, "child": child})
}

func (s *MongoStore) ParentOf(principal string) (string, error) {
	var pc parentChild
	err := s.parents.Find(bson.M{"child": principal}).One(&pc)
	if err == mgo.ErrNotFound {
		return "", affinity.NotFound
	}
	if err != nil {
		return "", err
	}
	return pc.parent, nil
}

func (s *MongoStore) InsertGrant(principal, role, resource string) error {
	return s.grants.Insert(bson.M{
		"principal": principal,
		"role":      role,
		"resource":  resource,
	})
}

func (s *MongoStore) RemoveGrant(principal, role, resource string) error {
	return s.grants.Remove(bson.M{
		"principal": principal,
		"role":      role,
		"resource":  resource,
	})
}

func (s *MongoStore) ResourceGrants(resource string) (principals, roles []string, err error) {
	var grants []grant
	err = s.grants.Find(bson.M{"resource": resource}).All(&grants)
	if err != nil {
		return
	}
	for i := range grants {
		principals = append(principals, grants[i].principal)
		roles = append(roles, grants[i].role)
	}
	return
}

func (s *MongoStore) PrincipalGrants(principal string, effective bool) (roles, resources []string, err error) {
	var grants []grant
	var parentErr error
	for parentErr == nil && effective {
		err = s.grants.Find(bson.M{"principal": principal}).All(&grants)
		if err != nil {
			return
		}
		for i := range grants {
			roles = append(roles, grants[i].role)
			resources = append(resources, grants[i].resource)
		}
		principal, parentErr = s.ParentOf(principal)
	}
	return
}

func (s *MongoStore) RoleGrants(principal, resource string, effective bool) (roles []string, err error) {
	var grants []grant
	var parentErr error
	for parentErr == nil && effective {
		err = s.grants.Find(bson.M{"principal": principal, "resource": resource}).All(&grants)
		if err != nil {
			return
		}
		for i := range grants {
			roles = append(roles, grants[i].role)
		}
		principal, parentErr = s.ParentOf(principal)
	}
	return
}

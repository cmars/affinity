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
)

type mongoStore struct {
	*mgo.Session
	db *mgo.Database
	c  *mgo.Collection
}

// DialMongoStore connects to MongoDB and uses an opinionated default for
// database and collection names.
func DialMongoStore(url string, dbuser, dbpass string) (rbac.FactStore, error) {
	session, err := mgo.Dial(url)
	if err != nil {
		return nil, err
	}
	db := session.DB("affinity")
	if dbuser != "" {
		err := db.Login(dbuser, dbpass)
		if err != nil {
			return nil, err
		}
	}
	return NewFactStore(session, db, "rbac")
}

// NewFactStore creates an rbac.FactStore over an established MongoDB session
// and database, using the given collection name for storing the facts.
func NewFactStore(session *mgo.Session, db *mgo.Database, collection string) (rbac.FactStore, error) {
	store := &mongoStore{Session: session, db: db}
	store.c = store.db.C(collection)

	err := store.db.C(collection).EnsureIndex(mgo.Index{
		Key:    []string{"subject", "predicate", "object", "topic"},
		Unique: true,
	})
	if err != nil {
		return nil, err
	}

	return store, nil
}

func (s *mongoStore) Assert(facts ...rbac.Fact) error {
	var docs []interface{}
	for _, fact := range facts {
		docs = append(docs, fact)
	}
	err := s.c.Insert(docs...)
	if err != nil && !mgo.IsDup(err) {
		return err
	}
	return nil
}

func (s *mongoStore) Deny(facts ...rbac.Fact) error {
	for _, fact := range facts {
		err := s.c.Remove(fact)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *mongoStore) Exists(facts ...rbac.Fact) (bool, error) {
	for _, fact := range facts {
		n, err := s.c.Find(fact).Count()
		if err != nil {
			return false, err
		}
		if n > 0 {
			return true, err
		}
	}
	return false, nil
}

func (s *mongoStore) Match(fact rbac.Fact) ([]rbac.Fact, error) {
	var result []rbac.Fact
	where := bson.M{"topic": fact.Topic}
	if fact.Subject != "" {
		where["subject"] = fact.Subject
	}
	if fact.Predicate != "" {
		where["predicate"] = fact.Predicate
	}
	if fact.Object != "" {
		where["object"] = fact.Object
	}
	err := s.c.Find(where).All(&result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

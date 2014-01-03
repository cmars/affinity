package mongo

import (
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"

	. "github.com/cmars/affinity"
	"github.com/cmars/affinity/server"
)

type MongoStore struct {
	*mgo.Session
	db     *mgo.Database
	groups *mgo.Collection
}

func NewMongoStore(url string) (*MongoStore, error) {
	session, err := mgo.Dial(url)
	if err != nil {
		return nil, err
	}
	store := &MongoStore{Session: session}
	store.db = store.DB("affinity")
	store.groups = store.db.C("groups")

	err = store.groups.EnsureIndex(mgo.Index{
		Key:    []string{"id"},
		Unique: true,
	})
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (s *MongoStore) AddGroup(group *Group) error {
	_, err := s.groups.Upsert(bson.M{"id": group.Id}, group)
	return err
}

func (s *MongoStore) GetGroup(groupId string) (*Group, error) {
	g := new(Group)
	err := s.groups.Find(bson.M{"id": groupId}).One(g)
	if err != nil {
		if err == mgo.ErrNotFound {
			err = server.NotFound
		}
		return nil, err
	}
	return g, nil
}

func (s *MongoStore) DeleteGroup(groupId string) error {
	return s.groups.Remove(bson.M{"id": groupId})
}

func (s *MongoStore) AddMember(groupId string, user User) error {
	g, err := s.GetGroup(groupId)
	if err != nil {
		return err
	}
	for _, member := range g.Members {
		if member.Equals(user) {
			return nil
		}
	}
	g.Members = append(g.Members, user)
	_, err = s.groups.Upsert(bson.M{"id": g.Id}, g)
	return err
}

func (s *MongoStore) DeleteMember(groupId string, user User) error {
	g, err := s.GetGroup(groupId)
	if err != nil {
		return err
	}
	var has bool
	members := []User{}
	for _, member := range g.Members {
		if member.Equals(user) {
			has = true
		} else {
			members = append(members, member)
		}
	}
	if !has {
		return nil
	}
	g.Members = members
	_, err = s.groups.Upsert(bson.M{"id": g.Id}, g)
	return err
}

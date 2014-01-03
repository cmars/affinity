package server

import (
	"fmt"

	. "github.com/cmars/affinity"
)

var NotFound error = fmt.Errorf("Not found")

type Store interface {
	AddGroup(group *Group) error
	GetGroup(groupId string) (*Group, error)
	DeleteGroup(groupId string) error
	AddMember(groupId string, user User) error
	DeleteMember(groupId string, user User) error
}

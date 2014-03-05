package rbac_test

import (
	. "github.com/juju/affinity"
)

var messageBoardLastId int = 0

func (mb *mbConn) loadPage(pageNumber int) (string, error) {
	return "some stuff", nil
}

func (mb *mbConn) post(msg string) (int, error) {
	messageBoardLastId++
	return messageBoardLastId, nil
}

func (mb *mbConn) Ban(user User, nsecs int) error {
	panic("not impl")
}

func (mb *mbConn) Read(msgId int) (string, error) {
	panic("not impl")
}

func (mb *mbConn) Delete(msgId int) error {
	panic("not impl")
}

func (mb *mbConn) Sticky(msgId int) error {
	panic("not impl")
}

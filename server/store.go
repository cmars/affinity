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

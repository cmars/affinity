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

package affinity

import (
	"fmt"
	"strings"
)

type User struct {
	Scheme, Id string
}

func (u User) Equals(other User) bool {
	return u.Scheme == other.Scheme && u.Id == other.Id
}

func (u User) String() string {
	return fmt.Sprintf("%s:%s", u.Scheme, u.Id)
}

func ParseUser(s string) (u User, err error) {
	i := strings.LastIndex(s, ":")
	if i == -1 || i == 0 || i == len(s)-1 {
		return u, fmt.Errorf("Parse error: invalid User format '%v'", s)
	}
	return User{Scheme: s[0:i], Id: s[i+1:]}, nil
}

type Group struct {
	Id      string
	Admins  []User
	Members []User
}

func (g *Group) HasAdmin(user User) bool {
	for _, admin := range g.Admins {
		if user.Equals(admin) {
			return true
		}
	}
	return false
}

func (g *Group) HasMember(user User) bool {
	for _, member := range g.Members {
		if user.Equals(member) {
			return true
		}
	}
	return false
}

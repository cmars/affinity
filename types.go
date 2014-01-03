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

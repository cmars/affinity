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

package mem

import (
	"github.com/juju/affinity/rbac"
)

type memStore struct {
	facts map[rbac.Fact]bool
}

func NewFactStore() rbac.FactStore {
	return &memStore{
		facts: make(map[rbac.Fact]bool),
	}
}

func (s *memStore) Assert(facts ...rbac.Fact) error {
	for _, t := range facts {
		s.facts[t] = true
	}
	return nil
}

func (s *memStore) Deny(facts ...rbac.Fact) error {
	for _, t := range facts {
		delete(s.facts, t)
	}
	return nil
}

func (s *memStore) Exists(facts ...rbac.Fact) (bool, error) {
	var match bool
	for _, t := range facts {
		_, match = s.facts[t]
		if !match {
			return match, nil
		}
	}
	return match, nil
}

func (s *memStore) Match(pattern rbac.Fact) ([]rbac.Fact, error) {
	var result []rbac.Fact
	for t := range s.facts {
		if rbac.MatchFact(pattern, t) {
			result = append(result, t)
		}
	}
	return result, nil
}

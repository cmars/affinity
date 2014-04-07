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

package rbac

// Fact is a statement that can be asserted in a knowledge base.
type Fact struct {
	Topic                      string
	Subject, Predicate, Object string
}

// Matches reports whether a fact matches a concrete fact as a pattern.  Empty
// strings for Subject, Predicate or Object are interpreted as a wildcard.
func MatchFact(pattern, concrete Fact) bool {
	return ((pattern.Topic == concrete.Topic) &&
		((pattern.Subject == concrete.Subject) || pattern.Subject == "") &&
		((pattern.Predicate == concrete.Predicate) || pattern.Predicate == "") &&
		((pattern.Object == concrete.Object) || pattern.Object == ""))
}

// FactStore is a simple collection of unique, assertable, searchable facts.
type FactStore interface {
	// Assert ensures facts are in the store (idempotent).
	Assert(facts ...Fact) error
	// Deny ensures facts are not in the store (idempotent).
	Deny(facts ...Fact) error
	// Exists reports whether all facts have been asserted.
	Exists(facts ...Fact) (bool, error)
	// Match returns facts in the store matching the pattern of the provided
	// fact. Empty strings are treated as wildcards. No match returns an
	// empty result, not an error.
	Match(fact Fact) ([]Fact, error)
}

const (
	groupTopic  = "affinity:groups"
	Isa         = "is-a"
	GroupObject = "group"
	MemberOf    = "member-of"
)

// GroupFacts adds subject grouping to facts. A fact made on a group subject
// is fully transitive to all its descendant members.
type GroupFacts struct {
	store FactStore
}

// NewGroupFacts creates a GroupFacts instance over the given FactStore.
func NewGroupFacts(backing FactStore) *GroupFacts {
	return &GroupFacts{store: backing}
}

func (s *GroupFacts) Assert(facts ...Fact) error {
	return s.store.Assert(facts...)
}

func (s *GroupFacts) Deny(facts ...Fact) error {
	return s.store.Deny(facts...)
}

func (s *GroupFacts) Exists(facts ...Fact) (bool, error) {
	return s.store.Exists(facts...)
}

func (s *GroupFacts) Match(fact Fact) ([]Fact, error) {
	return s.store.Match(fact)
}

// IsGroup returns whether a given subject is a group.
func (s *GroupFacts) IsGroup(subject string) (bool, error) {
	// Find the assertion that this is a group.
	isa, err := s.store.Match(Fact{
		Topic:     groupTopic,
		Subject:   subject,
		Predicate: Isa,
		Object:    GroupObject,
	})
	return len(isa) > 0, err
}

// AddGroup defines a new, empty subject group.
func (s *GroupFacts) AddGroup(group string) error {
	// Declare that the group is a group.
	return s.store.Assert(Fact{
		Topic:     groupTopic,
		Subject:   group,
		Predicate: Isa,
		Object:    GroupObject,
	})
}

// AddMember adds a subject to a group. The group is created if it did not
// already exist.
func (s *GroupFacts) AddMember(group, member string) error {
	if err := s.AddGroup(group); err != nil {
		return err
	}
	return s.store.Assert(Fact{
		Topic:     groupTopic,
		Subject:   member,
		Predicate: MemberOf,
		Object:    group,
	})
}

func (s *GroupFacts) RemoveMember(group, member string) error {
	return s.store.Deny(Fact{
		Topic:     groupTopic,
		Subject:   member,
		Predicate: MemberOf,
		Object:    group,
	})
}

func (s *GroupFacts) RemoveGroup(group string) error {
	var deny []Fact
	// Find all member-of assertions on this group.
	members, err := s.store.Match(Fact{Predicate: MemberOf, Object: group})
	if err != nil {
		return err
	}
	deny = append(deny, members...)
	// Find the assertion that this is a group.
	isa, err := s.store.Match(Fact{
		Topic:     groupTopic,
		Subject:   group,
		Predicate: Isa,
		Object:    GroupObject,
	})
	if err != nil {
		return err
	}
	// Deny everything.
	deny = append(deny, isa...)
	return s.store.Deny(deny...)
}

// Groups returns the groups which the given subject is a member of.
func (s *GroupFacts) Groups(member string) ([]string, error) {
	var result []string
	stmts, err := s.store.Match(Fact{
		Topic:     groupTopic,
		Subject:   member,
		Predicate: MemberOf,
	})
	if err != nil {
		return nil, err
	}

	for _, stmt := range stmts {
		result = append(result, stmt.Object)
	}
	return result, nil
}

// MatchAll returns all facts that match a fact for the given subject and the
// set of all its containing groups.
func (s *GroupFacts) MatchAll(start Fact) ([]Fact, error) {
	var result []Fact
	visited := make(map[string]bool)
	pending := []Fact{start}
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]

		matches, err := s.store.Match(current)
		if err != nil {
			return nil, err
		}

		visited[current.Subject] = true
		for _, match := range matches {
			result = append(result, match)
		}

		// Queue up facts for groups containing the current subject
		groups, err := s.Groups(current.Subject)
		if err != nil {
			return nil, err
		}
		for _, group := range groups {
			if _, ok := visited[group]; !ok {
				// Queue up only groups we haven't seen yet.
				groupFact := start
				groupFact.Subject = group
				pending = append(pending, groupFact)
			}
		}
	}
	return result, nil
}

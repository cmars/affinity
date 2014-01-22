package util

type StringSet map[string]bool

func UniqueStrings(items []string) []string {
	var result []string
	u := make(map[string]bool)
	for _, item := range items {
		u[item] = true
	}
	for item := range u {
		result = append(result, item)
	}
	return result
}

func NewStringSet(items []string) StringSet {
	result := make(StringSet)
	for _, item := range items {
		result[item] = true
	}
	return result
}

func (ss StringSet) AddAll(items ...string) {
	for _, item := range items {
		ss[item] = true
	}
}

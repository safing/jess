package hashtools

import (
	"errors"
	"fmt"
	"hash"
	"sort"
)

var (
	hashToolMap  = make(map[string]*HashTool)
	hashToolList = sortableHashToolList{}

	// ErrNotFound is returned when a hash tool cannot be found.
	ErrNotFound = errors.New("does not exist")
)

// Register registers a new HashTool. This function may only be called in init() functions.
func Register(hashTool *HashTool) {
	hashToolMap[hashTool.Name] = hashTool
	hashToolList = append(hashToolList, hashTool)
	sort.Sort(hashToolList)
}

// Get returns the HashTool with the given name.
func Get(name string) (*HashTool, error) {
	hashTool, ok := hashToolMap[name]
	if !ok {
		return nil, fmt.Errorf("tool %s %w", name, ErrNotFound)
	}
	return hashTool, nil
}

// New returns a new hash.Hash with the given name.
func New(name string) (hash.Hash, error) {
	hashTool, err := Get(name)
	if err != nil {
		return nil, err
	}

	return hashTool.New(), nil
}

// AsMap returns all HashTools in a map. The returned map must not be modified.
func AsMap() map[string]*HashTool {
	return hashToolMap
}

// AsList returns all HashTools in a slice. The returned slice must not be modified.
func AsList() []*HashTool {
	return hashToolList
}

type sortableHashToolList []*HashTool

// Len implements sort.Interface.
func (l sortableHashToolList) Len() int { return len(l) }

// Swap implements sort.Interface.
func (l sortableHashToolList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

// Less implements sort.Interface.
func (l sortableHashToolList) Less(i, j int) bool { return l[i].Name < l[j].Name }

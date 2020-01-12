package tools

import (
	"fmt"
	"sort"
)

var (
	toolMap  = make(map[string]*Tool)
	toolList = sortableToolList{}
)

// Register registers a new Tool. This function may only be called in init() functions.
func Register(tool *Tool) {
	// register in lists
	toolMap[tool.Info.Name] = tool
	toolList = append(toolList, tool)
	sort.Sort(toolList)
}

// Get returns the Tool with the given name.
func Get(name string) (*Tool, error) {
	tool, ok := toolMap[name]
	if !ok {
		return nil, fmt.Errorf("Tool %s %w", name, ErrNotFound)
	}
	return tool, nil
}

// New returns a new instance of a Tool's Logic with the given name.
func New(name string) (ToolLogic, error) {
	tool, err := Get(name)
	if err != nil {
		return nil, err
	}

	return tool.Factory(), nil
}

// AsMap returns all Tools in a map. The returned map must not be modified.
func AsMap() map[string]*Tool {
	return toolMap
}

// AsList returns all Tools in a slice. The returned slice must not be modified.
func AsList() []*Tool {
	return toolList
}

type sortableToolList []*Tool

// Len implements sort.Interface.
func (l sortableToolList) Len() int { return len(l) }

// Swap implements sort.Interface.
func (l sortableToolList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }

// Less implements sort.Interface.
func (l sortableToolList) Less(i, j int) bool { return l[i].Info.Name < l[j].Info.Name }

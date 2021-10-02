package jess

import (
	"github.com/safing/jess/tools"

	// Import all tools.
	_ "github.com/safing/jess/tools/all"
)

func init() {
	// init static logic
	for _, tool := range tools.AsList() {
		tool.StaticLogic = tool.Factory()
		tool.StaticLogic.Init(
			tool,
			&Helper{
				session: nil,
				info:    tool.Info,
			},
			nil,
			nil,
		)
	}
}

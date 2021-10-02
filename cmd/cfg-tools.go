package main

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"

	"github.com/safing/jess/hashtools"
	"github.com/safing/jess/tools"
)

func pickTools(toolNames []string, promptMsg string) ([]string, error) { //nolint:unused,deadcode // TODO
	var toolSelection [][]string //nolint:prealloc
	preSelectedTools := make([]string, 0, len(toolNames))
	var preSelected int

	// place already configured tools at top
	for _, toolName := range toolNames {
		toolID := toolName
		if strings.Contains(toolID, "(") {
			toolID = strings.Split(toolID, "(")[0]
		}

		tool, err := tools.Get(toolID)
		if err != nil {
			return nil, err
		}

		toolSelection = append(toolSelection, []string{
			toolName,
			tool.Info.FormatPurpose(),
			formatToolSecurityLevel(tool),
			tool.Info.Author,
			tool.Info.Comment,
		})
		preSelectedTools = append(preSelectedTools, tool.Info.Name)

		preSelected++
	}

	// add all other tools
	for _, tool := range tools.AsList() {
		if stringInSlice(tool.Info.Name, preSelectedTools) {
			continue
		}

		toolSelection = append(toolSelection, []string{
			tool.Info.Name,
			tool.Info.FormatPurpose(),
			formatToolSecurityLevel(tool),
			tool.Info.Author,
			tool.Info.Comment,
		})
	}

	// select
	var selectedEntries []string
	formattedColumns := formatColumns(toolSelection)
	selectTools := &survey.MultiSelect{
		Message:  promptMsg,
		Options:  formattedColumns,
		Default:  formattedColumns[:preSelected],
		PageSize: 15,
	}
	err := survey.AskOne(selectTools, &selectedEntries, nil)
	if err != nil {
		return nil, err
	}

	// check selection
	newTools := make([]string, 0, len(selectedEntries))
	for _, entry := range selectedEntries {
		toolName := strings.Fields(entry)[0]
		if strings.Contains(toolName, "(") {
			newTools = append(newTools, toolName)
			continue
		}

		// get tool
		tool, err := tools.Get(toolName)
		if err != nil {
			return nil, err
		}

		// check if tool needs hasher
		if tool.Info.HasOption(tools.OptionNeedsDedicatedHasher) ||
			tool.Info.HasOption(tools.OptionNeedsManagedHasher) {
			// add hash tool
			hashToolName, err := pickHashTool(fmt.Sprintf("Select hash tool for %s:", toolName), tool.Info.SecurityLevel)
			if err != nil {
				return nil, err
			}
			newTools = append(newTools, fmt.Sprintf("%s(%s)", toolName, hashToolName))
		} else {
			newTools = append(newTools, toolName)
		}
	}

	return newTools, nil
}

func pickHashTool(prompt string, minSecurityLevel int) (string, error) { //nolint:unused // TODO
	var hashToolSelection [][]string
	for _, hashTool := range hashtools.AsList() {
		if hashTool.SecurityLevel >= minSecurityLevel {
			hashToolSelection = append(hashToolSelection, []string{
				hashTool.Name,
				fmt.Sprintf("%d b/s", hashTool.SecurityLevel),
				hashTool.Author,
				hashTool.Comment,
			})
		}
	}
	var selectedEnty string
	selectHashTool := &survey.Select{
		Message:  prompt,
		Options:  formatColumns(hashToolSelection),
		PageSize: 15,
	}
	err := survey.AskOne(selectHashTool, &selectedEnty, nil)
	if err != nil {
		return "", err
	}
	return strings.Fields(selectedEnty)[0], nil
}

func stringInSlice(s string, a []string) bool { //nolint:unused // TODO
	for _, entry := range a {
		if entry == s {
			return true
		}
	}
	return false
}

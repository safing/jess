package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/safing/jess"
	"github.com/safing/jess/tools"
)

func formatColumns(table [][]string) []string {
	buf := bytes.NewBuffer(nil)

	// format table with tab writer
	tabWriter := tabwriter.NewWriter(buf, 8, 4, 3, ' ', 0)
	for i := 0; i < len(table); i++ {
		if i > 0 {
			// linebreak
			fmt.Fprint(tabWriter, "\n")
		}
		fmt.Fprint(tabWriter, strings.Join(table[i], "\t"))
	}
	tabWriter.Flush()

	// parse to []string
	var lines []string
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil
	}

	return lines
}

func formatSecurityLevel(securityLevel int) string {
	return fmt.Sprintf("%d b/s", securityLevel)
}

func formatToolSecurityLevel(tool *tools.Tool) string {
	if tool.Info.HasOption(tools.OptionNeedsSecurityLevel) {
		return "dynamic b/s (set manually via --seclevel)"
	}
	if tool.Info.SecurityLevel == 0 {
		return ""
	}
	return formatSecurityLevel(tool.Info.SecurityLevel)
}

func formatSignetName(signet *jess.Signet) string {
	switch {
	case signet.Info != nil && signet.Info.Name != "":
		return signet.Info.Name
	case signet.ID != "":
		return signet.ID
	default:
		return "[unknown]"
	}
}

func formatSignetType(signet *jess.Signet) string {
	switch {
	case signet.Scheme == jess.SignetSchemeKey:
		return "key"
	case signet.Scheme == jess.SignetSchemePassword:
		return "password"
	case signet.Public:
		return "recipient"
	default:
		return "signet"
	}
}

func formatSignetScheme(signet *jess.Signet) string {
	switch signet.Scheme {
	case jess.SignetSchemeKey, jess.SignetSchemePassword:
		return ""
	default:
		return signet.Scheme
	}
}

func formatSignetPurpose(signet *jess.Signet) string {
	switch signet.Scheme {
	case jess.SignetSchemeKey, jess.SignetSchemePassword:
		return ""
	}

	tool, err := signet.Tool()
	if err != nil {
		return "[unknown]"
	}
	return tool.Info.FormatPurpose()
}

func formatSignetSecurityLevel(signet *jess.Signet) string {
	switch signet.Scheme {
	case jess.SignetSchemeKey, jess.SignetSchemePassword:
		return ""
	}

	tool, err := signet.Tool()
	if err != nil {
		return failPlaceholder
	}

	securityLevel, err := tool.StaticLogic.SecurityLevel(signet)
	if err != nil {
		if err == tools.ErrProtected {
			return "[protected]"
		}
		return failPlaceholder
	}

	return fmt.Sprintf("%d b/s", securityLevel)
}

func formatRequirements(reqs *jess.Requirements) string {
	if reqs == nil || reqs.Empty() {
		return "none (unsafe)"
	}
	return reqs.String()
}

func formatSignetNames(signets []*jess.Signet) string {
	names := make([]string, 0, len(signets))
	for _, signet := range signets {
		names = append(names, formatSignetName(signet))
	}
	return strings.Join(names, ", ")
}

func formatEnvelopeSignets(envelope *jess.Envelope) string {
	var sections []string
	if len(envelope.Secrets) > 0 {
		sections = append(sections, fmt.Sprintf("Secrets: %s", formatSignetNames(envelope.Secrets)))
	}
	if len(envelope.Recipients) > 0 {
		sections = append(sections, fmt.Sprintf("To: %s", formatSignetNames(envelope.Recipients)))
	}
	if len(envelope.Senders) > 0 {
		sections = append(sections, fmt.Sprintf("From: %s", formatSignetNames(envelope.Senders)))
	}
	return strings.Join(sections, ", ")
}

func formatSuiteStatus(suite *jess.Suite) string {
	switch suite.Status {
	case jess.SuiteStatusDeprecated:
		return "DEPRECATED"
	case jess.SuiteStatusRecommended:
		return "recommended"
	default:
		return ""
	}
}

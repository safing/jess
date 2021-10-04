package main

import (
	"errors"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"

	"github.com/safing/jess"
	"github.com/safing/jess/tools"
)

//nolint:gocognit
func newSignet(name, scheme string) (*jess.Signet, error) {
	// get name
	name = strings.TrimSpace(name)
	if name == "" {
		enterName := &survey.Input{
			Message: "Enter name of signet:",
		}
		err := survey.AskOne(enterName, &name, survey.WithValidator(survey.MinLength(1)))
		if err != nil {
			return nil, err
		}
	}

	// get scheme
	scheme = strings.TrimSpace(scheme)
	if scheme == "" {
		// build selection list
		schemeSelection := [][]string{
			{jess.SignetSchemePassword, "Password"},
			{jess.SignetSchemeKey, "Key", "dynamic b/s (set manually via --symkeysize)"},
			{"ECDH-X25519", "Receiving (KeyExchange)"},
			{"Ed25519", "Signing"},
		}

		// select scheme
		selectScheme := &survey.Select{
			Message: "Select Tool/Scheme:",
			Options: formatColumns(schemeSelection),
		}
		err := survey.AskOne(selectScheme, &scheme, nil)
		if err != nil {
			return nil, err
		}
		scheme = strings.Fields(scheme)[0]
	}

	// generate key
	var signet *jess.Signet

	switch scheme {
	case jess.SignetSchemePassword:
		signet = &jess.Signet{
			Version: 1,
			Scheme:  jess.SignetSchemePassword,
		}

	case jess.SignetSchemeKey:
		signet = &jess.Signet{
			Version: 1,
			Scheme:  jess.SignetSchemeKey,
		}
		if defaultSymmetricKeySize == 0 {
			return nil, errors.New("missing key size, please supply with --symkeysize")
		}
		newKey, err := jess.RandomBytes(defaultSymmetricKeySize)
		if err != nil {
			return nil, err
		}
		signet.Key = newKey

	default:
		// get tool
		tool, err := tools.Get(scheme)
		if err != nil {
			return nil, err
		}

		// create base
		signet = jess.NewSignetBase(tool)

		// check if tool needs security level or manual key size
		if tool.Info.HasOption(tools.OptionNeedsSecurityLevel) && minimumSecurityLevel <= 0 {
			return nil, errors.New("missing security level, please supply with --seclevel")
		}
		if tool.Info.HasOption(tools.OptionNeedsDefaultKeySize) && defaultSymmetricKeySize <= 0 {
			return nil, errors.New("missing key size, please supply with --symkeysize")
		}

		// generate
		err = signet.GenerateKey()
		if err != nil {
			return nil, err
		}
		err = signet.StoreKey()
		if err != nil {
			return nil, err
		}
	}

	err := signet.AssignUUID()
	if err != nil {
		return nil, err
	}
	signet.Info = &jess.SignetInfo{
		Name:    name,
		Created: time.Now(),
	}

	// write signet
	err = trustStore.StoreSignet(signet)
	if err != nil {
		return nil, err
	}

	// export as recipient
	switch scheme {
	case jess.SignetSchemePassword, jess.SignetSchemeKey:
		// is secret, no recipient
	default:
		rcpt, err := signet.AsRecipient()
		if err != nil {
			return nil, err
		}
		err = rcpt.StoreKey()
		if err != nil {
			return nil, err
		}
		err = trustStore.StoreSignet(rcpt)
		if err != nil {
			return nil, err
		}
	}

	return signet, nil
}

func selectSignets(envelope *jess.Envelope, scope string) error {
	// collect all signet schemes that fit the scope
	var schemes []string
	var promptMsg string
	var currentSignets []*jess.Signet
	filter := jess.FilterSignetOnly
	switch scope {
	case jess.SignetSchemePassword:
		schemes = []string{jess.SignetSchemePassword}
		promptMsg = "Select password references: (selection is AND, not OR!)"
	case jess.SignetSchemeKey:
		schemes = []string{jess.SignetSchemeKey}
		promptMsg = "Select keys: (selection is AND, not OR!)"
	case "pw/key":
		schemes = []string{jess.SignetSchemePassword, jess.SignetSchemeKey}
		promptMsg = "Select keys and password references: (selection is AND, not OR!)"
		currentSignets = envelope.Secrets
	case "recipient": //nolint:goconst
		promptMsg = "Select recipients: (selection is AND, not OR!)"
		for _, tool := range tools.AsList() {
			switch tool.Info.Purpose {
			case tools.PurposeKeyExchange,
				tools.PurposeKeyEncapsulation:
				schemes = append(schemes, tool.Info.Name)
			}
		}
		filter = jess.FilterRecipientOnly
		currentSignets = envelope.Recipients
	case "sender":
		promptMsg = "Select senders: (selection is AND, not OR!)"
		for _, tool := range tools.AsList() {
			if tool.Info.Purpose == tools.PurposeSigning {
				schemes = append(schemes, tool.Info.Name)
			}
		}
		currentSignets = envelope.Senders
	default:
		return errors.New("unknown signet selection scope")
	}

	// collect all signet for the scope's schemes
	signetCandidates, err := trustStore.SelectSignets(filter, schemes...)
	if err != nil {
		return err
	}
	if len(signetCandidates) == 0 {
		return errors.New("no signets available, please create some first using the generate command")
	}

	// select signets
	selectedSignets, err := pickSignet(signetCandidates, promptMsg, "", true, currentSignets)
	if err != nil {
		return err
	}

	// make stubs
	selectedSignetStubs := make([]*jess.Signet, 0, len(selectedSignets))
	for _, signet := range selectedSignets {
		selectedSignetStubs = append(selectedSignetStubs, &jess.Signet{
			ID: signet.ID,
		})
	}

	// add signets to envelope
	switch scope {
	case "pw", "key", "pw/key":
		envelope.Secrets = selectedSignetStubs
	case "recipient":
		envelope.Recipients = selectedSignetStubs
	case "sender":
		envelope.Senders = selectedSignetStubs
	}

	return nil
}

func pickSignet(signetOptions []*jess.Signet, promptMsg, doneMsg string, multi bool, multiPreselected []*jess.Signet) ([]*jess.Signet, error) {
	// compile list
	signetSelection := make([][]string, 0, len(signetOptions)+1)
	var preSelected int
	if !multi && doneMsg != "" {
		signetSelection = append(signetSelection, []string{doneMsg})
	}
	if multi {
		for _, signet := range multiPreselected {
			signetSelection = append(signetSelection, []string{
				formatSignetName(signet),
				formatSignetType(signet),
				formatSignetScheme(signet),
				formatSignetPurpose(signet),
				formatSignetSecurityLevel(signet),
				signet.ID,
			})
			preSelected++
		}
	}
signetOptionLoop:
	for _, signet := range signetOptions {
		// do not add pre-selected signets
		if multi {
			for _, preSelectedSignet := range multiPreselected {
				if signet.ID == preSelectedSignet.ID &&
					signet.Public == preSelectedSignet.Public {
					continue signetOptionLoop
				}
			}
		}
		signetSelection = append(signetSelection, []string{
			formatSignetName(signet),
			formatSignetType(signet),
			formatSignetScheme(signet),
			formatSignetPurpose(signet),
			formatSignetSecurityLevel(signet),
			signet.ID,
		})
	}

	// select signet/s
	var selectedEntries []string
	if multi {
		formattedColumns := formatColumns(signetSelection)
		selectSignets := &survey.MultiSelect{
			Message:  promptMsg,
			Options:  formattedColumns,
			Default:  formattedColumns[:preSelected],
			PageSize: 15,
		}
		err := survey.AskOne(selectSignets, &selectedEntries, nil)
		if err != nil {
			return nil, err
		}
	} else {
		var selectedEnty string
		selectSignet := &survey.Select{
			Message:  promptMsg,
			Options:  formatColumns(signetSelection),
			PageSize: 15,
		}
		err := survey.AskOne(selectSignet, &selectedEnty, nil)
		if err != nil {
			return nil, err
		}
		// check for done msg
		if strings.HasPrefix(selectedEnty, doneMsg+" ") {
			return nil, nil
		}
		selectedEntries = []string{selectedEnty}
	}

	// get selected signet/s
	var selectedSignets []*jess.Signet
selectedEntriesLoop:
	for _, entry := range selectedEntries {
		fields := strings.Fields(entry)
		id := fields[len(fields)-1] // last entry
		if multi {
			for _, signet := range multiPreselected {
				if id == signet.ID {
					selectedSignets = append(selectedSignets, signet)
					continue selectedEntriesLoop
				}
			}
		}
		for _, signet := range signetOptions {
			if id == signet.ID {
				selectedSignets = append(selectedSignets, signet)
				continue selectedEntriesLoop
			}
		}
	}

	return selectedSignets, nil
}

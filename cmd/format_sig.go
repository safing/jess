package main

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/safing/jess/filesig"
)

func formatSignatures(filename, signame string, fds []*filesig.FileData) string {
	b := &strings.Builder{}

	switch len(fds) {
	case 0:
	case 1:
		formatSignature(b, fds[0])
	case 2:
		for _, fd := range fds {
			fmt.Fprintf(b, "%d Signatures:\n\n\n", len(fds))
			formatSignature(b, fd)
			b.WriteString("\n\n")
		}
	}

	if filename != "" || signame != "" {
		b.WriteString("\n")
		fmt.Fprintf(b, "File: %s\n", filename)
		fmt.Fprintf(b, "Sig:  %s\n", signame)
	}

	return b.String()
}

func formatSignature(b *strings.Builder, fd *filesig.FileData) {
	if fd.VerificationError() == nil {
		b.WriteString("Verification: OK\n")
	} else {
		fmt.Fprintf(b, "Verification FAILED: %s\n", fd.VerificationError())
	}

	if letter := fd.Signature(); letter != nil {
		b.WriteString("\n")
		for _, sig := range letter.Signatures {
			signet, err := trustStore.GetSignet(sig.ID, true)
			if err == nil {
				fmt.Fprintf(b, "Signed By: %s (%s)\n", signet.Info.Name, sig.ID)
			} else {
				fmt.Fprintf(b, "Signed By: %s\n", sig.ID)
			}
		}
	}

	if fileHash := fd.FileHash(); fileHash != nil {
		b.WriteString("\n")
		fmt.Fprintf(b, "Hash Alg: %s\n", fileHash.Algorithm())
		fmt.Fprintf(b, "Hash Sum: %s\n", hex.EncodeToString(fileHash.Sum()))
	}

	if len(fd.MetaData) > 0 {
		b.WriteString("\nMetadata:\n")

		sortedMetaData := make([][]string, 0, len(fd.MetaData))
		for k, v := range fd.MetaData {
			sortedMetaData = append(sortedMetaData, []string{k, v})
		}
		sort.Sort(sortByMetaDataKey(sortedMetaData))
		for _, entry := range sortedMetaData {
			fmt.Fprintf(b, "    %s: %s\n", entry[0], entry[1])
		}
	}
}

type sortByMetaDataKey [][]string

func (a sortByMetaDataKey) Len() int           { return len(a) }
func (a sortByMetaDataKey) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortByMetaDataKey) Less(i, j int) bool { return a[i][0] < a[j][0] }

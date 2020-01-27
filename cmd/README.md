### Jess CLI

This is currently still more of a planning and working document.  
Here is the CLI interface that is planned:

```
jess create <envelope file>

jess close <file> with <envelope name>
	encrypt a file, write to file with the same name, but with a .letter suffix
	-o <file> ... write output to <file>

jess open <file>
	decrypt a file, write to file with the same name, but without the .letter suffix
	-o <file> ... write output to <file>

jess sign <file> with <envelope>
	same as close, but will put the signature in a separate file called <file>.seal

jess verify <file>
	verifies the signature(s), but does not decrypt

jess show <file>
	shows all available information about said file. File can be
	- envelope
	- letter
	- seal (signature-only letter)

jess generate
    generate a new signet and store both signet and recipient in the truststore

global arguments
    --tsdir /path/to/truststore
    --seclevel <uint>
    --symkeysize <uint>
    --quiet only output errors and warnings
```

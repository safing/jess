/*
CLI:

jess create <envelope file>

jess close <file> with <envelope file>
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

global arguments
--tsdir /path/to/truststore
--seclevel <uint>
--symkeysize <uint>
--quiet only output errors and warnings

*/
package main

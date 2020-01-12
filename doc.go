/*
jess is a lovely cat that protects your data.

Jess uses four types of objects:
- Envelopes (encryption configuration)
- Letters (encrypted data)
- Stamp (private or secret key)
- Signet (certificate / public key)
- Seal (separate signature)

Usage:

	message := "I love milk"

	// configure
	envelope, err := jess.NewEnvelope().SupplyPassword("paw").Check()

	// encrypt
	letter := jess.Close(envelope, message)
	encrypted := letter.AsString()
	fmt.Println(encrypted)

	// decrypt
	letter = jess.LetterFromString(encrypted)
	message = jess.Open(envelope, letter)
	fmt.Println(message)

CLI: coming soon

	jess new <envelope>
	// create new configuration

	jess close <file> with <envelope>
	// encrypt data in a letter

	jess open <file>
	// decrypt and verify letter

	jess show <file>
	// show information about object

	jess sign <file> with <envelope>
	// special close case, where only a signature is created and put in a separate `.seal` file

Internals:

Envelope.Correspondence() *Session



Key Establishment


Exchange:

c=IDLE s=IDLE

c -> new ephemeral public key -> s
... detected by len(keys) > 0
c=AWAIT_KEY, s=SEND_KEY

s: make new ephemeral key, apply new shared secret immediately
s -> new ephemeral public key -> c
... detected by len(keys) > 0
c: apply new shared secret immediately for s->c
c=SEND_APPLY, s=AWAIT_APPLY

c: apply new shared secret to c->s
c -> apply -> s
... detected by APPLY flag
s: apply to c->s
c=IDLE, S=IDLE

Encapsulation:

c=IDLE s=IDLE

c -> new ephemeral public key -> s
... detected by len(keys) > 0
c=AWAIT_KEY, s=SEND_KEY

s: make key, apply immediately and encapsulate
s -> encapsulated key -> c
... detected by len(keys) > 0
c: apply encapsulated key immediately for s->c
c=SEND_APPLY, s=AWAIT_APPLY

c: apply encapsulated secret for c->s
c -> apply -> s
... detected by APPLY flag
s: apply to c->s
c=IDLE, S=IDLE

*/

package jess

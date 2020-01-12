# Jess Specification

## Basics

The basic building blocks of jess are:

#### Envelope

Envelopes hold the configuration for cryptographic operations.

Given an envelope and and a message, jess creates a letter, an encrypted container that also holds any information needed to successfully open the letter, if the keys/passwords are supplied.

#### Letter

Given an envelope and and a message, jess creates a letter - an encrypted container that also holds any information needed to successfully open the letter, if the keys/passwords are supplied.

#### Signet / Recipient

Signets hold secrets, such as a private key. Recipients represents the public (ie. secret-less) versions of signets.

#### Seal

Seals hold key establishment data, such as public keys or encapsulated keys.

## Stored Data

The basic ability of jess is to open and close letters - discrete data blobs, such as a file stored on disk.

## Wire Protocol

The wire protocol is requires the Confidentiality, Integrity and RecipientAuthentication requirements.

Keys are established using ephemeral keys and are re-established frequently, providing forward secrecy:
- Even if the static key is compromised, data encrypted in the past will remain secured.
- An attacker must execute an active Man-in-the-Middle attack or continually compromise all ephermal keys in order to sustain full compromise.
- If a session key is compromised, only encrypted data until the next key re-establishment will be compromised.

Continually evolving session keys provide backward secrecy:
- Even if a session key is compromised, data encrypted before the compromise remains secured.

Connections are established in a 0-RTT (zero round trip time) manner, enabling the first message to carry data. The caveat is that until the first key establishment has fully finished, transmitted data from the client to the server will be only protected by the static key (ie. without forward secrecy).

When used for tunneling or with a sub-protocol, this usually won't be an issue, as the sub-protocol will most likely have a synchronous establishment procedure anyway, guaranteeing a full key establishment when the sub-protocol is finished with it's own setup.

There will be a way to force a full establishment before transmitting data in the future.

This protocol is also inspired by the Double Ratchet Algorithm.

If you are familiar with the Noise Protocol Framework, you will notice that this protocol is very similar to the "NK handshake". The main difference is that the handshake of this protocol is asynchronous, is periodically repeated and it uses evolving keys, making it suitable for long lived high-volume connections.

Currently, all key establishment elements and signatures are not hidden and can be seen on the wire. This will change in a future protocol version. Also, signatures, pre-shared keys and passwords - as part of the handshake - are not yet supported and future support is uncertain.

### Key Establishment Procedure with DH Based Algorithm

`init only` signifies steps that are only performed in the initial handshake. Other steps are performed for both the initial handshake and renewals. The semi-ephemeral keys `[se]` are rather short-lived keys (hours to days), that are securely distributed in a seperate manner.

<svg xmlns="http://www.w3.org/2000/svg" id="mainsvg" width="731.720703125" height="382" viewBox="-10 -10 731.720703125 382"><defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"/></marker><filter id="shadowfilter" x="-20%" y="-20%" width="150%" height="150%" filterUnits="objectBoundingBox" primitiveUnits="userSpaceOnUse" color-interpolation-filters="linearRGB"><feDropShadow stdDeviation="4 4" in="SourceGraphic" dx="1" dy="1" flood-color="#BABABA" flood-opacity="0.9" x="0%" y="0%" width="100%" height="100%" result="dropShadow"/></filter><filter id="shadowfilter2" x="0" y="0" width="200%" height="200%" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0"/><feOffset dy="4" dx="2"/><feGaussianBlur stdDeviation="2"/><feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.25 0"/><feBlend mode="normal" in2="BackgroundImageFix" result="effect1_dropShadow"/><feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow" result="shape"/></filter></defs><g transform="translate(0, 0)"><rect width="55.5390625" height="38" stroke="#555656" fill="white" stroke-width="1.3" transform="translate(0, 0)" rx="2" filter="url(#shadowfilter)"/><text fill="black" font-size="16" font-weight="normal" transform="translate(10, 19)" alignment-baseline="middle" font-family="Bookman"> client </text></g><g transform="translate(150.287109375, 0)"><rect width="59.0859375" height="38" stroke="#555656" fill="white" stroke-width="1.3" transform="translate(0, 0)" rx="2" filter="url(#shadowfilter)"/><text fill="black" font-size="16" font-weight="normal" transform="translate(10, 19)" alignment-baseline="middle" font-family="Bookman"> server </text></g><path d="M 27.76953125,50 L 37.76953125 50 L 37.76953125 68 L 27.76953125 68" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 179.830078125,80 L 189.830078125 80 L 189.830078125 98 L 179.830078125 98" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,110 L 37.76953125 110 L 37.76953125 128 L 27.76953125 128" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,162 L 179.830078125 162" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 179.830078125,170 L 189.830078125 170 L 189.830078125 188 L 179.830078125 188" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 179.830078125,200 L 189.830078125 200 L 189.830078125 218 L 179.830078125 218" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 179.830078125,252 L 27.76953125 252" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,260 L 37.76953125 260 L 37.76953125 278 L 27.76953125 278" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,312 L 179.830078125 312" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 179.830078125,320 L 189.830078125 320 L 189.830078125 338 L 179.830078125 338" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,38 L 27.76953125 362" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1"/><path d="M 179.830078125,38 L 179.830078125 362" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1"/><g transform="translate(39.76953125, 50)"><rect width="166.404296875" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">generates ephemeral key [e1]</text></g><g transform="translate(191.830078125, 80)"><rect width="347.228515625" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">init only: generates semi-ephemeral key [se] and distributes it</text></g><g transform="translate(39.76953125, 110)"><rect width="401.3828125" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">init only: makes secret [s1] from [e1, se], applies it to [client—&gt;server]</text></g><g transform="translate(54.97900390625, 140)"><rect width="97.6416015625" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">sends public [e1]</text></g><g transform="translate(191.830078125, 170)"><rect width="401.3828125" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">init only: makes secret [s1] from [se, e1], applies it to [client—&gt;server]</text></g><g transform="translate(191.830078125, 200)"><rect width="519.890625" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">generates ephemeral key [e2], makes secret [s2] from [e2, e1], applies it to [client&lt;—server]</text></g><g transform="translate(54.97900390625, 230)"><rect width="97.6416015625" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">sends public [e2]</text></g><g transform="translate(39.76953125, 260)"><rect width="472.216796875" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">makes secret [s2] from [e1, e2], applies it to [client&lt;—server] and [client—&gt;server]</text></g><g transform="translate(51.76953125, 290)"><rect width="104.060546875" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">sends APPLY flag</text></g><g transform="translate(191.830078125, 320)"><rect width="217.4755859375" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">applies secret [s2] to [client—&gt;server]</text></g></svg>

<!--
edit here:
www.diagram.codes/d/sequence

source:
alias c="client"
alias s="server"

c->c: "generates ephemeral key [e1]"
s->s: "init only: generates semi-ephemeral key [se] and distributes it"
c->c: "init only: makes secret [s1] from [e1, se], applies it to [client—>server]"

c->s: "sends public [e1]"
s->s: "init only: makes secret [s1] from [se, e1], applies it to [client—>server]"
s->s: "generates ephemeral key [e2], makes secret [s2] from [e2, e1], applies it to [client<—server]"

s->c: "sends public [e2]"
c->c: "makes secret [s2] from [e1, e2], applies it to [client<—server] and [client—>server]"

c->s: "sends APPLY flag"
s->s: "applies secret [s2] to [client—>server]"
-->

### Key Establishment Procedure with Key Encapsulation

`init only` signifies steps that are only performed in the initial handshake. Other steps are performed for both the initial handshake and renewals. The semi-ephemeral keys `[se]` are rather short-lived keys (hours to days), that are securely distributed in a seperate manner.

<svg xmlns="http://www.w3.org/2000/svg" id="mainsvg" width="700.4599609375" height="412" viewBox="-10 -10 700.4599609375 412"><defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"/></marker><filter id="shadowfilter" x="-20%" y="-20%" width="150%" height="150%" filterUnits="objectBoundingBox" primitiveUnits="userSpaceOnUse" color-interpolation-filters="linearRGB"><feDropShadow stdDeviation="4 4" in="SourceGraphic" dx="1" dy="1" flood-color="#BABABA" flood-opacity="0.9" x="0%" y="0%" width="100%" height="100%" result="dropShadow"/></filter><filter id="shadowfilter2" x="0" y="0" width="200%" height="200%" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0"/><feOffset dy="4" dx="2"/><feGaussianBlur stdDeviation="2"/><feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.25 0"/><feBlend mode="normal" in2="BackgroundImageFix" result="effect1_dropShadow"/><feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow" result="shape"/></filter></defs><g transform="translate(0, 0)"><rect width="55.5390625" height="38" stroke="#555656" fill="white" stroke-width="1.3" transform="translate(0, 0)" rx="2" filter="url(#shadowfilter)"/><text fill="black" font-size="16" font-weight="normal" transform="translate(10, 19)" alignment-baseline="middle" font-family="Bookman"> client </text></g><g transform="translate(159.8232421875, 0)"><rect width="59.0859375" height="38" stroke="#555656" fill="white" stroke-width="1.3" transform="translate(0, 0)" rx="2" filter="url(#shadowfilter)"/><text fill="black" font-size="16" font-weight="normal" transform="translate(10, 19)" alignment-baseline="middle" font-family="Bookman"> server </text></g><path d="M 27.76953125,50 L 37.76953125 50 L 37.76953125 68 L 27.76953125 68" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 189.3662109375,80 L 199.3662109375 80 L 199.3662109375 98 L 189.3662109375 98" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,110 L 37.76953125 110 L 37.76953125 128 L 27.76953125 128" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,162 L 189.3662109375 162" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,192 L 189.3662109375 192" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 189.3662109375,200 L 199.3662109375 200 L 199.3662109375 218 L 189.3662109375 218" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 189.3662109375,230 L 199.3662109375 230 L 199.3662109375 248 L 189.3662109375 248" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 189.3662109375,282 L 27.76953125 282" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,290 L 37.76953125 290 L 37.76953125 308 L 27.76953125 308" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,342 L 189.3662109375 342" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 189.3662109375,350 L 199.3662109375 350 L 199.3662109375 368 L 189.3662109375 368" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1" marker-end="url(#arrow)"/><path d="M 27.76953125,38 L 27.76953125 392" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1"/><path d="M 189.3662109375,38 L 189.3662109375 392" fill="none" stroke="black" stroke-dasharray="none" stroke-width="1"/><g transform="translate(39.76953125, 50)"><rect width="166.404296875" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">generates ephemeral key [e1]</text></g><g transform="translate(201.3662109375, 80)"><rect width="347.228515625" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">init only: generates semi-ephemeral key [se] and distributes it</text></g><g transform="translate(39.76953125, 110)"><rect width="531.990234375" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">init only: creates secret [s1], applies it to [client—&gt;server], encapsulates it with [se] to get [c1]</text></g><g transform="translate(59.7470703125, 140)"><rect width="97.6416015625" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">sends public [e1]</text></g><g transform="translate(51.76953125, 170)"><rect width="113.5966796875" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">init only: sends [c1]</text></g><g transform="translate(201.3662109375, 200)"><rect width="388.1689453125" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">init only: gets secret [s1] from [se, c1], applies it to [client—&gt;server]</text></g><g transform="translate(201.3662109375, 230)"><rect width="479.09375" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">creates secret [s2], applies it to [client&lt;—server], encapsulates it with [e1] to get [c2]</text></g><g transform="translate(78.99365234375, 260)"><rect width="59.1484375" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">sends [c2]</text></g><g transform="translate(39.76953125, 290)"><rect width="459.0029296875" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">gets secret [s2] from [e1, c2], applies it to [client&lt;—server] and [client—&gt;server]</text></g><g transform="translate(56.53759765625, 320)"><rect width="104.060546875" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">sends APPLY flag</text></g><g transform="translate(201.3662109375, 350)"><rect width="217.4755859375" height="18" stroke="none" fill="white" stroke-width="1" transform="translate(0, 0)" rx="5"/><text fill="black" font-size="14" font-weight="normal" transform="translate(1, 9)" alignment-baseline="middle">applies secret [s2] to [client—&gt;server]</text></g></svg>

<!--
edit here:
www.diagram.codes/d/sequence

source:
alias c="client"
alias s="server"

c->c: "generates ephemeral key [e1]"
s->s: "init only: generates semi-ephemeral key [se] and distributes it"
c->c: "init only: creates secret [s1], applies it to [client—>server], encapsulates it with [se] to get [c1]"

c->s: "sends public [e1]"
c->s: "init only: sends [c1]"
s->s: "init only: gets secret [s1] from [se, c1], applies it to [client—>server]"
s->s: "creates secret [s2], applies it to [client<—server], encapsulates it with [e1] to get [c2]"

s->c: "sends [c2]"
c->c: "gets secret [s2] from [e1, c2], applies it to [client<—server] and [client—>server]"

c->s: "sends APPLY flag"
s->s: "applies secret [s2] to [client—>server]"
-->

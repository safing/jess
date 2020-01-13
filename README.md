# Jess

Jess is a cryptographic library and cli tool that focuses on usability and freedom.

DISCLAIMER: This is still work in progress. Breaking changes might still occur. Do _not_ use in production yet! Use at your own risk.

### Usage & Intro

Jess uses the theme of envelopes and letters in order to make everything a bit more comprehensible. Here is a list of terms that will prove helpful:
- __Signet__ private or secret key
- __Recipient__ public key
- __Envelope__ encryption configuration
- __Letter__ encrypted data with associated configuration
- __Trust Store__ a storage of everything you trust, your own keys and configurations, and your friends' public keys.

Jess makes heavy use of `trust stores`, which in its basic form is just a directory, where you can store your keys and configuration. You can either set a default through an environment variable, or set it manually every time. This makes it easy to compartmentalize your trust zones.

Here is how you can setup a trust store and generate some keys:

    export JESS_TSDIR=/tmp/truststore-test
    jess generate --name Alice --scheme Ed25519
    jess generate --name Alice --scheme ECDH-X25519
    jess generate --name Bob --scheme Ed25519
    jess generate --name Bob --scheme ECDH-X25519
    jess generate --name BackupPassword --scheme pw
    # look at result
    jess manage

Now let's configure an envelope to get started with encrypting - set up an envelope to have Alice send Bob a file. Use the preset `Encrypt for someone`.

    jess configure toBob
    # look at result
    jess manage

If now want to encrypt a file for Bob, you take a piece of data, put it in the envelope, and you have a letter!

    echo "Hello, Bob!" > forbob.txt
    jess close forbob.txt with toBob

And because we also have Bob's secret key, we can also go ahead and decrypt the file again.

    jess open forbob.txt.letter -o -

Normally, of course, you would have a friend send you their `recipient` file (public key) and you would add it to your trust store.

In order to help you not screw up any configuration, Jess has the concept of __requirements__:
- Confidentiality ... hide contents
- Integrity ... check that nothing was modified
- Recipient Authentication ... verify identity of recipient
- Sender Authentication ... verify identity of sender

By default, all of them are required. If you, for some reason, do not require one ore more of them, you will have to disable them in the envelope for closing an envelope (encrypting) and pass the reduced requirements when opening a letter (decrypting).

In addition, if you are worried about weak algorithms, you can just pass a minimum security level (attack complexity as 2^n) that you require all algorithms to achieve. Jess does not contain any known weak algorithms, but if that changes, jess will warn you - after you upgraded to the new version.

Jess does not have a PKI or some sort of web of trust. You have to exchange public keys by yourself.

Jess is also capable of securing a network connection, but this currently only works with the library, not the CLI.

### Building

Jess uses [dep](https://github.com/golang/dep) as the dependency manager.  
After cloning the repo, run `dep ensure`.

The command line tool includes build information for debugging.  
Please use the provided build script for building:
```
cd cmd
./build -o jess
./jess version
```

### Architecture

Before we dive into technical details, here are some more/updated terms:
- __Tool/Scheme__ a cryptographic primitive/scheme
  - Identified via their Name/ID (used interchangeably)
- __Signet/Recipient__ a private/secret or public key
  - Identified by their ID (usually a UUID)
- __Envelope__ an encryption configuration, but also requirements
  - Identified by the name given to them

Every algorithm/piece that can be used to _build_ a complete encryption operation is called a Tool. Tools have different capabilites and might cover more than just one primitive - eg. AES-GCM covers _Confidentiality_ and _Integrity_.

Jess can either operate in _single-op_ (eg. file encryption) or _communication_ (eg. securing network traffic) mode.

Basically, every operation needs:
- _SenderAuthentication_ and _ReceiverAuthentication_:
  - `PassDerivation`: derive a key from given password
    - provides _SenderAuthentication_, _ReceiverAuthentication_
  - `KeyExchange`: supply trusted public key of peer _comm mode only_
    - provides _ReceiverAuthentication_
  - `KeyEncapsulation`: encrypt the key with trusted public key of peer
    - provides _ReceiverAuthentication_
  - `Signing`: sign the whole message
    - provides _SenderAuthentication_
- _KeyDerivation_: guarantees clean key material, also more material than given may be needed.
- _Confidentiality_:
  - `Cipher`: encrypt the data
  - `IntegratedCipher`: also provides _Integrity_
- _Integrity_:
  - `MAC`: check data integrity
  - `IntegratedCipher`: also provides _Confidentiality_

Some of these properties may also be used multiple times. For example, you could choose to encrypt your data with multiple ciphers or use multiple MACs for data integrity checks.

Should any of these properties _not_ be required, the user has to intentionally remove requirements.

### Specification

There is some more detail in [SPEC.md](./SPEC.md).

### Testing

Basically, tests are run like this:
```
go test
```

There is a special variable to enable very comprehensive testing:

```
go test -timeout 10m github.com/safing/jess -v -count=1 -cover -ldflags "-X github.com/safing/jess.RunComprehensiveTests=true"
```

There is some randomness to this, so you can use this command for predictable output in order to debug a problem:

```
go test -timeout 10m github.com/safing/jess -v -count=1 -cover -ldflags "-X github.com/safing/jess.RunComprehensiveTests=true -X github.com/safing/jess.RunTestsInDebugStyle=true"

# if you only want the comprehensive test itself:
go test -timeout 10m github.com/safing/jess -run ^TestCoreAllCombinations$ -v -count=1 -cover -ldflags "-X github.com/safing/jess.RunComprehensiveTests=true -X github.com/safing/jess.RunTestsInDebugStyle=true"
```

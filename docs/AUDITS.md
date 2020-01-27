# Audits

## Audit #001

In January 2020, the project was audited by [Cure53](https://cure53.de/).  
Cure53 was chosen because they have proven to both excell as auditors as well as being committed to building a more open and better Internet - I mean, just have a look at their [publications](https://cure53.de/#publications)!

[This commit](https://github.com/safing/jess/commit/648d16d1cc8185ed3704373e43c84a6ab4315498) was handed in for the audit.  
Fixes can be found in [PR #3](https://github.com/safing/jess/pull/3) and was merged [here](https://github.com/safing/jess/commit/41fbc87f119a7d69f0fd9f24275e245fd4e2eedf).

They found 5 issues:

__Secure key deletion ineffective (Medium Severity)__  
Golang does not yet provide a secure way of handling key material. The is no clean fix, we were advised to wait. Documentation has been updated to reflect this.  
See [Github issue](https://github.com/golang/go/issues/21865) for details.

__Password KDF vulnerable to GPU/ASIC attacks (Medium Severity)__  
PBKDF2 is vulnarable to GPU/ASIC attacks, was replaced with scrypt with a much higher security margin (rounds).

__Secure channel protocol weaknesses (High Severity)__  
Verification of the protocol with [Verifpal](https://verifpal.com) revealed that in addition to one expected weakness, there is another. The found weakness should actually have been expected, because it is a limitation of the protocol. The main use case of the protocol, securing SPN connections, is not impacted. Documentation was updated.

__Key management/encryption with 1-byte key (Critical Severity)__  
This was just a devops error. We forgot to replace a "FIXME" comment with a function call. 🙈

__Unnecessary configurability considered dangerous (Medium Severity)__  
This was somewhat expected. We did not yet know how to best expose the configurability to users. We were advised: NOT. We implemented changes and introduced cipher suites that specify a fixed sets of algorithms and security guarantees.

The full report is available [in-repo here](audit_001_report_cure53_SAF-01.pdf) or [directly from the auditor](https://cure53.de/pentest-report_safing-jess.pdf).

# Formal Verification

In the first Audit by Cure53, one of the auditors, [Nadim Kobeissi](https://nadim.computer/), used his software [Verifpal](https://verifpal.com/) for an automated formal verficiation of the wire protocol. This was quite an amazing thing, as we wrote the model definition _in_ the kickoff meeting. Verifpal then combed through the model to check if it really holds up to its promises. You can find the model [here](key_establishment_dh.vp).

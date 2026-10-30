# Security policy

## Reporting a vulnerability

Report privately through GitHub's **private vulnerability reporting** for this
repository (Security tab, then "Report a vulnerability"). Do not open public
issues for security problems.

Please include the affected document or component, a description, and steps to
reproduce or a proof-of-concept argument. During the specification phase,
design flaws in consensus rules, cryptographic choices, or launch procedures are
in scope and very welcome.

## What this project will never do

- Ask for a seed phrase, private key, or wallet file.
- Contact you first through direct messages.
- Sell coins, run a presale, or announce an airdrop.
- Ship auto-updating node software.

## Release verification (future)

Releases will be reproducible builds, signed by multiple independent builders,
with published checksums. A release signature attests that a binary matches the
source. It is not consensus authority.

## AI-assisted work

Parts of this repository were drafted with AI assistance. AI review is not a
security audit. Mainnet will not launch without independent human review of the
cryptography, consensus, networking, and wallet code.

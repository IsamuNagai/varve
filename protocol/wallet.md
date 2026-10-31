# Wallet keys, derivation and backup (standard, draft v0.2)

Not consensus. This is the interoperability standard wallets SHOULD follow so a
backup made in one wallet restores in another (audit finding M-10). Nothing
here is frozen; it needs review by people who build wallets and hardware.

## 1. Constraints that differ from Bitcoin

- **No public derivation.** ML-DSA and SLH-DSA have no equivalent of BIP-32
  non-hardened derivation, so there is no "xpub". Every key is derived from the
  secret seed. Watch-only wallets need an exported list of commitments (§6).
- **Addresses are one-time.** Spending reveals the public key. A wallet MUST
  NOT reuse an address after any output sent to it has been spent, and SHOULD
  NOT reuse addresses at all.
- **Keygen is deterministic from a seed** in both standards: ML-DSA-65
  `KeyGen_internal(ξ)` takes a 32-byte `ξ` (FIPS 204); SLH-DSA-SHA2-128s
  `slh_keygen_internal(SK.seed, SK.prf, PK.seed)` takes three 16-byte values
  (FIPS 205). Signing stays hedged (randomized), so deterministic keys do not
  mean deterministic signatures.
- The interoperable backup is the seed (§2), not a secret key. Secret-key
  encodings (e.g. liboqs's 4,032-byte expanded ML-DSA-65 key) are local to an
  implementation and MUST NOT be part of any exchange format.

## 2. Seeds

- A **seed** is 32 bytes of entropy from a cryptographically secure source.
- It is shown to the user as **24 words** from the BIP-39 English word list
  (256 bits of entropy plus an 8-bit SHA-256 checksum, exactly as BIP-39
  encodes entropy). The words encode the seed itself. The BIP-39 PBKDF2
  "mnemonic to seed" step is **not** used, so a Varve phrase entered into a
  Bitcoin wallet produces unrelated keys, and vice versa.
- An optional passphrase is mixed in as below. Losing it loses the funds.

      master = SHAKE256(u8(len(T)) ‖ T ‖ seed ‖ u16(len(pass)) ‖ pass, 64)   with T = "VARVE/wallet/master/v1"

  `pass` is the UTF-8 NFKD-normalized passphrase (empty if none), at most
  65,535 bytes. An implementation that cannot apply NFKD MUST refuse
  passphrases it cannot normalize (the reference implementation accepts ASCII
  only, for which NFKD is the identity) rather than use unnormalized bytes.

Parsing a phrase: lowercase it, split on any whitespace, require exactly 24
words, each found exactly in the English list (no prefix matching), and a
matching checksum. Anything else is rejected.

## 3. Primary and recovery seeds are separate

A recovery path only adds safety if the recovery key is held apart from the
primary key (transactions.md §8.1). So:

- A wallet that creates policy-1 outputs uses **two seeds**: a primary seed,
  and a recovery seed that the user stores elsewhere or gives to the person who
  should be able to recover (an heir, a second device in a safe).
- A wallet MAY offer a "self-recovery" mode where both are derived from one
  seed (role byte differs), for users who only want protection against losing
  a device and not against losing the seed. It MUST explain that this mode
  gives no protection if the seed itself is lost or stolen.

## 4. Key derivation

For each key:

    okm = SHAKE256(u8(len(T)) ‖ T ‖ master ‖ u8(role) ‖ u16(scheme_id) ‖ u32(account) ‖ u32(index), L)
    T = "VARVE/wallet/key/v1"

- `role`: 0 = primary, 1 = recovery.
- `scheme_id`: `0x0001` → `L = 32`, `ξ = okm`; `0x0002` → `L = 48`,
  `SK.seed = okm[0:16]`, `SK.prf = okm[16:32]`, `PK.seed = okm[32:48]`.
- `account`: starts at 0. `index`: increments for every new address.
- Integers little-endian, as everywhere in Varve.
- The default receive address `n` is role 0, scheme `0x0001`, account 0,
  index `n`, as a policy-0 output (addresses.md).

## 5. Scanning and gap limit

Because keys can only be derived from the secret, a restoring wallet derives
indexes 0, 1, 2, … for each role and scheme it supports and looks for outputs
whose commitment matches. It stops after **100** consecutive unused indexes
(higher than Bitcoin's usual 20, since every receive needs a fresh address).

## 6. Watch-only export

A watch-only wallet receives a list of output templates (or their
commitments) for indexes `0 … n`, plus the derivation parameters, and is
re-exported when it runs low. It can see and track coins but cannot spend.

## 7. Hardware wallets

Signing must happen on the device: an ML-DSA-65 signature is 3,309 bytes and
an SLH-DSA-SHA2-128s signature takes much longer to make than to verify.
Devices need to display amount, destination address and spending path
(primary or recovery) before signing. The sighash (transactions.md §7) needs
every spent output, so the device must receive the spent outputs to verify
amounts, not just a hash.

## 8. Encrypted wallet file ("strata-wallet-v1")

A wallet stored on disk SHOULD use this format so files move between wallets.
It is encrypt-then-MAC.

**Keys.** `K = Argon2id(P = pass, S = salt, K = "", X = "", m, t, p, T = 64)`,
Argon2 version 0x13 (RFC 9106). `pass` follows the passphrase rule of §2.
`enc_key = K[0:32]`, `mac_key = K[32:64]`. `salt` is 16 fresh random bytes
per encryption.

**Parameters.** Writers use `m = 65536` KiB (64 MiB), `t = 3`, `p = 1` unless
the user chooses otherwise within the accepted ranges. Readers MUST reject,
before running the KDF, any file with `m` outside `8192 … 1048576` KiB
(8 MiB – 1 GiB), `t` outside `1 … 10`, or `p` outside `1 … 4`, so a hostile
file cannot demand unbounded memory or time. Writers MUST NOT go below the
minimums.

**Cipher.** AES-256-CTR (NIST SP 800-38A) with `enc_key`. The initial counter
block is `iv`, 16 fresh random bytes. The last 4 bytes of the counter block
are a big-endian block counter; the first 12 never change. A writer MUST
draw a new `iv` until `u32be(iv[12:16]) + ceil(len/16) ≤ 2^32`, and a reader
MUST reject files that violate this, so 32-bit and 128-bit counter
implementations agree. Plaintext is at most 1 MiB.

**MAC.** `mac = HMAC-SHA256(mac_key, M)` (RFC 2104) with

    M = u8(16) ‖ "strata-wallet-v1" ‖ u8(8) ‖ "argon2id" ‖ u32(0x13) ‖ u32(m) ‖ u32(t) ‖ u32(p)
        ‖ salt ‖ u8(11) ‖ "aes-256-ctr" ‖ iv ‖ u64(len(ciphertext)) ‖ ciphertext

compared in constant time. Readers verify the MAC before decrypting.

**Container.** UTF-8 JSON, no insignificant whitespace, object keys in
ascending byte order, integers in shortest decimal, byte strings as lowercase
hex:

    {"cipher":{"iv":<hex16>,"name":"aes-256-ctr"},"ciphertext":<hex>,"format":"strata-wallet-v1",
     "kdf":{"m_kib":m,"name":"argon2id","p":p,"salt":<hex16>,"t":t,"version":19},"mac":<hex32>}

(shown wrapped; the real text is one line). Readers ignore leading and
trailing spaces, tabs, CR and LF and MUST reject everything else that differs from
this canonical text: unknown or missing fields, other spellings, uppercase
hex. A different `format`, `kdf.name`, `kdf.version` or `cipher.name` is an
unknown format. A wrong passphrase and a modified file give the same error.

**Wallet payload.** For a §2 wallet the plaintext is
`u8(1) ‖ seed ‖ u16(len(pass)) ‖ pass` (the seed passphrase, so a restored
file yields the same keys). Other payload versions are rejected.

## 9. Test vectors

`test-vectors/wallet.json`: a public test seed with and without a passphrase →
mnemonic → master → the first three ML-DSA-65 receive keys (plus a recovery
key, an account-1 key and an SLH-DSA key) → SHA3-256 of each public key,
commitment, template, mainnet and testnet address. It contains no `okm` or
secret keys. Seeded key generation in the reference implementation
(liboqs `keypair_internal`, `slh_keygen_internal`) is checked against the
NIST ACVP keyGen vectors for both schemes.

## 10. Open questions

- Whether to use BIP-39 words at all, or a word list with stronger
  error detection.
- Whether the seed passphrase step (§2) should be a memory-hard KDF to slow
  guessing; this costs time on hardware wallets. (Wallet files already use
  Argon2id, §8.)
- Recovery-key storage guidance for non-technical users, and refresh
  reminders before `recovery_delay` passes (§8.1 of transactions.md).
- Multi-device and multi-party custody without a script language.

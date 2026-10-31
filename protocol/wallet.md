# Wallet keys, derivation and backup (standard, draft v0.1)

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

## 2. Seeds

- A **seed** is 32 bytes of entropy from a cryptographically secure source.
- It is shown to the user as **24 words** from the BIP-39 English word list
  (256 bits of entropy plus an 8-bit SHA-256 checksum, exactly as BIP-39
  encodes entropy). The words encode the seed itself. The BIP-39 PBKDF2
  "mnemonic to seed" step is **not** used, so a Varve phrase entered into a
  Bitcoin wallet produces unrelated keys, and vice versa.
- An optional passphrase is mixed in as below. Losing it loses the funds.

      master = SHAKE256(u8(len(T)) ‖ T ‖ seed ‖ u16(len(pass)) ‖ pass, 64)   with T = "VARVE/wallet/master/v1"

  `pass` is the UTF-8 NFKD-normalized passphrase (empty if none).

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

## 8. Open questions

- Whether to use BIP-39 words at all, or a word list with stronger
  error detection.
- Whether the passphrase step should be a memory-hard KDF (Argon2id) to slow
  guessing; this costs time on hardware wallets.
- Recovery-key storage guidance for non-technical users, and refresh
  reminders before `recovery_delay` passes (§8.1 of transactions.md).
- Multi-device and multi-party custody without a script language.
- Test vectors (seed → master → first keys → commitments → addresses) once
  liboqs or another reference exposes seeded key generation for both schemes.

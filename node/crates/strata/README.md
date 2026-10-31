# Strata, the Varve wallet

Strata is the desktop wallet for Varve. It is a small program that runs on your
computer and opens its interface in your web browser. Testnet software:
testnet coins have no value. Mainnet has not launched.

## Use it

1. Download the file for your system from the
   [releases page](https://github.com/IsamuNagai/varve/releases) and check it
   against `SHA256SUMS`.
2. Unpack it and start `strata` (`strata.exe` on Windows). It opens
   `http://127.0.0.1:<port>/` in your browser.
3. Create a wallet or import your 24-word recovery phrase. Write the words on
   paper: anyone with them can take your coins, and they are the only way to
   recover the wallet.

Strata reads balances and history from a Varve node's public API
([`node/API.md`](../../API.md)). By default that is a node on your own computer
(`varve node --api-port 39911`). You can point it at a public `https://`
endpoint under Settings.

Options: `strata [--network testnet|regtest] [--port N] [--no-browser] [--datadir DIR]`.

The wallet file lives in `~/.local/share/strata` on Linux,
`~/Library/Application Support/Strata` on macOS and `%APPDATA%\Strata` on
Windows, with one folder per network.

## How it protects you

- **Keys stay on your computer.** Keys are derived from your recovery phrase
  ([`protocol/wallet.md`](../../../protocol/wallet.md)) inside the Strata
  program and are never sent to the browser page or to any server. Every
  payment is signed locally.
- **Encrypted wallet file.** Argon2id (64 MiB) protects your passphrase, and
  the file is encrypted with AES-256-CTR and authenticated with HMAC-SHA256.
  Unlocking is rate-limited, and the wallet locks itself after 10 idle minutes.
- **Locked-down local server.** It listens on 127.0.0.1 only and requires a
  random session token. It refuses requests addressed to any other host name
  (DNS rebinding) and refuses cross-site requests. A strict Content Security
  Policy forbids scripts from anywhere else, and there are no external
  resources, trackers or third-party code.
- **Untrusted node data.** Before signing, Strata checks every coin the node
  reports against your own keys, byte for byte. Because a Varve signature
  commits to every coin it spends, a dishonest node can at worst hide coins or
  make a payment fail. It cannot redirect your money.
- **You see exactly what you sign.** The review screen shows the recipient,
  amount, fee and change computed by the program that signs.

Limits to know about: a dishonest node can show a wrong balance or history;
passphrases are limited to ASCII; and anything that can read your browser or
your computer's memory while the wallet is unlocked can see your secrets. Keep
your computer clean and up to date.

## Tests

`cargo test -p strata` (unit tests), `node/tests/strata_e2e.py` (payments
against a real regtest node) and `node/tests/strata_ui.py` (the interface in a
real browser, desktop and mobile).

title: Strata wallet and Varvescan explorer
date: 2026-10-31

Two new pieces go live with the testnet: a wallet and a block explorer. Together with the node they make up what you need to use Varve, and all three now have a home on the new [Download page](download.html).

**Strata** is the Varve desktop wallet, for Windows, macOS and Linux. It runs on your own computer and opens in your browser. Create a wallet and you get a 24-word recovery phrase; your keys are derived from it inside Strata and never leave your machine. The wallet file is encrypted with your passphrase, Strata locks itself when you step away, and every payment is shown in full before it is signed. It takes advantage of a Varve feature from earlier this week: coins that belong to the same address are spent with a single signature, so even a payment that gathers dozens of small coins stays small and cheap. In our end-to-end test, one payment spent thirteen coins with one signature, and it confirmed on the next block.

**Varvescan** is the block explorer, built into this website. Look up any block, transaction or address: balances, full history, which keys a payment used, and where an address's coins came from. It runs in your browser with no cookies, trackers or third-party code, and it treats everything it receives as untrusted.

Both read from a new public interface in the node, which keeps its indexes exact through chain reorganisations and restarts; the multi-node tests now check that on every change.

There is also a [mainnet readiness](mainnet.html) page. It lists what is proven, what is designed, and what still has to happen before mainnet, and items only move to done with evidence you can check.

Next: the first public seed node goes online and the first testnet release is published, and you will be able to download all of this and start mining.

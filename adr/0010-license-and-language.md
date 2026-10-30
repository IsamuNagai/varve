# ADR-0010: License and implementation language

## Status
License: ACCEPTED (2026-10-30). Language: PROPOSED, to be decided before Phase 5.

## License decision
Dual **MIT OR Apache-2.0**. MIT is maximally permissive. Apache-2.0 adds an
explicit patent grant and patent-retaliation clause. Dual licensing is the
norm in the Rust ecosystem and lets downstream users choose. No proprietary
or custom license.

## Language (proposed): Rust

| Criterion | Rust | C++ | Go |
| --- | --- | --- | --- |
| Memory safety | Enforced (outside `unsafe`) | Manual | Garbage-collected |
| PQ crypto ecosystem | RustCrypto `ml-dsa` / `slh-dsa`, aws-lc-rs | liboqs, PQClean | circl (Cloudflare) |
| Determinism control | High | High | GC pauses, less control |
| Fuzzing | cargo-fuzz, libFuzzer | libFuzzer, AFL | native fuzzing |
| Reproducible builds | Achievable with a pinned toolchain | Achievable, more effort | Strong |
| RandomX binding | FFI to the C++ reference (an audit point) | Native | FFI |

**Leaning Rust.** The main open risk is RandomX: it is C++, so the FFI boundary
must be isolated and fuzzed. Any cryptography dependency needs a dependency
review (purpose, maintainers, audit history, transitive dependencies) before
it is adopted.

## Revisit trigger
The dependency review finds no audited Rust ML-DSA or SLH-DSA implementation
suitable for consensus use.

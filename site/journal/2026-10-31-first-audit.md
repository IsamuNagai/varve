title: The first independent review, and what it changed
date: 2026-10-31

An independent reviewer, who asked to stay anonymous, went through the protocol this week. A second, public review with a name attached will follow. I asked for the review to be adversarial, and it was. It found one critical issue and several high-severity ones, and I'm grateful for every one of them.

The critical one: an anti-spam rule in the sync logic could, in an edge case, keep a node on a chain with less work than a competing one. That breaks the most basic rule of proof of work. It is fixed, and the specification now states plainly that a node must always validate any chain with more work than its own.

Other fixes from the review:

- Real post-quantum signatures and real RandomX hashing are now tested on every change, on both x86_64 and ARM64. They were previously skipped in automated tests.
- The genesis procedure is now fully implemented and tested against real Bitcoin headers, including every possible one-byte tampering.
- A much larger test-vector suite, plus a second implementation of the rules written only from the specification. It agrees with the prototype on every vector.
- An emergency-migration idea that was only a sketch is no longer claimed as a feature. Varve promises only what is specified and tested.

Every finding and its resolution is public in `audits/`. This is how I want Varve built: find the problems early, fix them in the open, and never claim more than the code can back up.

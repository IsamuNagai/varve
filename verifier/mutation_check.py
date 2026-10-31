"""Vector coverage probe: break one rule at a time in varve_verify and report
which mutations the shipped test vectors fail to detect ("survivors").

A survivor is a consensus rule (or boundary) that the vectors do not pin down.
Each survivor is then run against selftest.py, to tell a rule the vectors miss
but the spec can exercise from one that no test can reach.
Usage: python3 -I verifier/mutation_check.py   (set VARVE_LIBOQS for full coverage)
"""

import contextlib
import io
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_vectors as rv  # noqa: E402
import selftest as st  # noqa: E402

SOURCE = open(os.path.join(HERE, "varve_verify.py")).read()

# (name, old text, new text); old text must occur exactly once.
MUTATIONS = [
    ("MTP: lower median for even-sized windows",
     "return sorted(window)[len(window) // 2]", "return sorted(window)[(len(window) - 1) // 2]"),
    ("MTP window 10", "MTP_WINDOW = 11", "MTP_WINDOW = 10"),
    ("MTP window 12", "MTP_WINDOW = 11", "MTP_WINDOW = 12"),
    ("timestamp >= MTP accepted",
     "if header.timestamp <= median_time_past(ancestors):", "if header.timestamp < median_time_past(ancestors):"),
    ("block weight limit is exclusive",
     "if total_weight > MAX_BLOCK_WEIGHT:", "if total_weight >= MAX_BLOCK_WEIGHT:"),
    ("block weight limit 720,001",
     "if total_weight > MAX_BLOCK_WEIGHT:", "if total_weight > MAX_BLOCK_WEIGHT + 1:"),
    ("block weight ignored", "if total_weight > MAX_BLOCK_WEIGHT:", "if False:"),
    ("coinbase weighed like a normal tx",
     "t.weight(coinbase=(i == 0))", "t.weight()"),
    ("weight without verify units",
     "units = sum(verify_units(len(w.signature)) for w in self.witnesses)", "units = 0"),
    ("weight without output-growth term",
     "UTXO_GROWTH_UNITS * max(0, len(self.outputs) - len(self.inputs))", "0"),
    ("locktime strict (height <= locktime)",
     "height < tx.locktime", "height <= tx.locktime"),
    ("coinbase prev_index not reduced mod 2^32",
     "prev_index != height % U32_LIMIT", "prev_index != height"),
    ("coinbase locktime always 0",
     "tx.locktime != height >> 32", "tx.locktime != 0"),
    ("coinbase witness extra limit 65",
     "len(w.signature) > COINBASE_EXTRA_MAX", "len(w.signature) > COINBASE_EXTRA_MAX + 1"),
    ("coinbase input count not enforced",
     'if len(tx.inputs) != 1 or prev_txid != ZERO32:', "if prev_txid != ZERO32:"),
    ("first tx need not be coinbase-shaped",
     "if not txs[0].is_coinbase_shaped():", "if False:"),
    ("zero prev_txid allowed in later txs",
     "if any(prev == ZERO32 for prev, _ in t.inputs):", "if False:"),
    ("duplicate txid check removed",
     "if len(set(txids)) != len(txids):", "if False:"),
    ("output sum cap removed", "if out_sum > MAX_MONEY:", "if False:"),
    ("output amount cap removed", "1 <= self.amount <= MAX_MONEY", "1 <= self.amount"),
    ("spent sum cap removed", "if in_sum > MAX_MONEY:", "if False:"),
    ("tx version unchecked", "if tx.version != 1:", "if False:"),
    ("empty input/output list allowed", "if not tx.inputs or not tx.outputs:", "if not tx.outputs:"),
    ("empty output list allowed", "if not tx.inputs or not tx.outputs:", "if not tx.inputs:"),
    ("output_version unchecked", "if self.output_version != 1:", "if False:"),
    ("recovery scheme creatability unchecked",
     "if not can_create(lifecycle, self.recovery_scheme_id, height):", "if False:"),
    ("recovery_delay may be 2^32-1",
     "1 <= self.recovery_delay <= RECOVERY_DELAY_MAX", "1 <= self.recovery_delay"),
    ("recovery_delay 0 allowed",
     "1 <= self.recovery_delay <= RECOVERY_DELAY_MAX", "self.recovery_delay <= RECOVERY_DELAY_MAX"),
    ("recovery delay inclusive off by one",
     "height < coin.height + o.recovery_delay", "height <= coin.height + o.recovery_delay"),
    ("recovery path allowed on single-policy output",
     "if o.policy != 1:", "if False:"),
    ("coinbase maturity 287",
     "height < coin.height + COINBASE_MATURITY", "height < coin.height + COINBASE_MATURITY - 1"),
    ("same-block coinbase output exempt from maturity",
     "if coin.coinbase and height < coin.height + COINBASE_MATURITY:",
     "if coin.coinbase and coin.height != height and height < coin.height + COINBASE_MATURITY:"),
    ("unknown parent accepted",
     "if header.prev_block != chain.headers[-1][2]:", "if False:"),
    ("trailing bytes after block accepted",
     'if r.remaining():\n        raise ParseError("trailing bytes")\n    return Block',
     "return Block"),
    ("tx_count 0 accepted", "if count < 1:", "if False:"),
    ("raw size bound removed", "if len(raw) > HEADER_LEN + 5 + MAX_BLOCK_WEIGHT:", "if False:"),
    ("path 1 selects the primary scheme and commitment",
     "return o.recovery_scheme_id, o.recovery_commitment",
     "return o.scheme_id, o.commitment"),
    ("ASERT: truncation instead of floor for negative exponent",
     "exponent = ((parent_time - t_a) - TARGET_SPACING * parent_height) * 65536 // ASERT_TAU",
     "_n = ((parent_time - t_a) - TARGET_SPACING * parent_height) * 65536\n"
     "    exponent = -((-_n) // ASERT_TAU) if _n < 0 else _n // ASERT_TAU"),
    ("ASERT: upper early return exclusive",
     "if exponent >= 256 * 65536:", "if exponent > 256 * 65536:"),
    ("ASERT: lower early return exclusive",
     "if exponent <= -270 * 65536:", "if exponent < -270 * 65536:"),
    ("ASERT: no rounding term", "+ 5127 * frac ** 3 + (1 << 47)) >> 48", "+ 5127 * frac ** 3) >> 48"),
    ("ASERT: clamp lower bound 0", "return max(1, min(t, pow_limit))", "return max(0, min(t, pow_limit))"),
    ("ASERT: no upper clamp", "return max(1, min(t, pow_limit))", "return max(1, t)"),
    ("subsidy: tail floor removed", "return max(decayed, TAIL_SUBSIDY)", "return decayed"),
    ("subsidy: epoch off by one", "epoch = (height - 1) // BLOCKS_PER_EPOCH", "epoch = height // BLOCKS_PER_EPOCH"),
    ("coinbase value ignores fees",
     "> subsidy(height) + total_fees:", "> subsidy(height):"),
    ("coinbase value cap removed", "> subsidy(height) + total_fees:", "> MAX_MONEY:"),
    ("merkle: odd node duplicated",
     "nxt.append(level[-1])  # carried unchanged, never duplicated",
     "nxt.append(h256(\"VARVE/merkle/node\", level[-1] + level[-1]))"),
    ("genesis t0 lower median", "t0 = times[3]", "t0 = times[2]"),
    ("anchor: H mod 2016 bound 2011", "if height % 2016 > 2010:", "if height % 2016 > 2011:"),
    ("anchor: powLimit unchecked", "if target > BITCOIN_POW_LIMIT:", "if False:"),
    ("compact: sign bit alone is negative",
     "if bits & 0x00800000 and word:", "if bits & 0x00800000:"),
    ("sighash: path omitted", "+ spent_hash + bytes([path]))", "+ spent_hash)"),
    # --- v0.4: anchored ASERT (difficulty.md §2, params.md) ---
    ("ASERT: anchor delay ignored (anchored at t0)",
     "t_a = t0 + ASERT_ANCHOR_DELAY", "t_a = t0"),
    ("ASERT: anchor delay with the wrong sign",
     "t_a = t0 + ASERT_ANCHOR_DELAY", "t_a = t0 - ASERT_ANCHOR_DELAY"),
    ("params: ASERT_ANCHOR_DELAY entry omitted",
     '        ("ASERT_ANCHOR_DELAY", "u32", ASERT_ANCHOR_DELAY),\n', ""),
    ("params: ASERT_ANCHOR_DELAY encoded as u64",
     '("ASERT_ANCHOR_DELAY", "u32", ASERT_ANCHOR_DELAY)', '("ASERT_ANCHOR_DELAY", "u64", ASERT_ANCHOR_DELAY)'),
    # --- v0.4: witness path 2 (encoding.md §1.5, transactions.md §8.2) ---
    ("parse: path 2 rejected", "if path not in (0, 1, 2):", "if path not in (0, 1):"),
    ("parse: path 3 accepted", "if path not in (0, 1, 2):", "if path not in (0, 1, 2, 3):"),
    ("path 2: non-empty public key allowed", "if w.public_key or w.signature:", "if w.signature:"),
    ("path 2: non-empty signature allowed", "if w.public_key or w.signature:", "if w.public_key:"),
    ("path 2: no authorizing input required",
     "if (o.scheme_id, o.commitment) not in authorized:", "if False:"),
    ("path 2: authorizer may be a later input",
     "authorized = set()  # (scheme, commitment) selected by earlier path-0/1 inputs",
     "authorized = {(c.output.scheme_id, c.output.commitment) if w.path == 0 else"
     " (c.output.recovery_scheme_id, c.output.recovery_commitment)"
     " for c, w in zip(coins, tx.witnesses) if w.path in (0, 1)}"),
    ("path 2: authorizer matched on commitment only",
     "if (o.scheme_id, o.commitment) not in authorized:",
     "if o.commitment not in {c for _s, c in authorized}:"),
    ("path 2: authorizer matched on scheme only",
     "if (o.scheme_id, o.commitment) not in authorized:",
     "if o.scheme_id not in {s for s, _c in authorized}:"),
    ("path 2: only path-0 inputs authorize",
     "        authorized.add((scheme, commitment))",
     "        if w.path == 0:\n            authorized.add((scheme, commitment))"),
    ("path 2: authorizer contributes its output's primary key even on path 1",
     "        authorized.add((scheme, commitment))", "        authorized.add((o.scheme_id, o.commitment))"),
    ("path 2: coinbase maturity not applied",
     "if coin.coinbase and height < coin.height + COINBASE_MATURITY:",
     "if coin.coinbase and w.path != 2 and height < coin.height + COINBASE_MATURITY:"),
    ("path 2: lifecycle state not checked",
     "if not can_spend(chain.lifecycle, o.scheme_id, height):", "if False:"),
    ("path 2: verify units charged for a path-2 entry",
     "units = sum(verify_units(len(w.signature)) for w in self.witnesses)",
     "units = sum(verify_units(len(w.signature)) if w.path != 2 else 100 for w in self.witnesses)"),
    # --- v0.4: lifecycle table (transactions.md §6) ---
    ("lifecycle: table ignored (always ACTIVE)",
     "    state, best = ACTIVE, -1\n    for entry_scheme", "    return ACTIVE\n    for entry_scheme"),
    ("lifecycle: creation allowed while NO_NEW_OUTPUTS",
     "return scheme_state(table, scheme_id, height) == ACTIVE",
     "return scheme_state(table, scheme_id, height) in (ACTIVE, NO_NEW_OUTPUTS)"),
    ("lifecycle: spending allowed while DISABLED",
     "return scheme_state(table, scheme_id, height) in (ACTIVE, NO_NEW_OUTPUTS)",
     "return scheme_state(table, scheme_id, height) is not None"),
    ("lifecycle: spending refused while NO_NEW_OUTPUTS",
     "return scheme_state(table, scheme_id, height) in (ACTIVE, NO_NEW_OUTPUTS)",
     "return scheme_state(table, scheme_id, height) == ACTIVE"),
    ("lifecycle: first matching transition instead of the greatest from_height",
     "            state, best = entry_state, from_height\n    return state",
     "            return entry_state\n    return state"),
    ("lifecycle: from_height exclusive", "from_height <= height:", "from_height < height:"),
    ("lifecycle: path 1 checked against the primary scheme's state",
     "if not can_spend(chain.lifecycle, scheme, height):",
     "if not can_spend(chain.lifecycle, o.scheme_id, height):"),
    ("lifecycle: recovery creatability checks the primary scheme",
     "if not can_create(lifecycle, self.recovery_scheme_id, height):",
     "if not can_create(lifecycle, self.scheme_id, height):"),
    ("lifecycle: creation checked at height 0, not the block height",
     "o.check_creatable(chain.lifecycle, height)", "o.check_creatable(chain.lifecycle, 0)"),
    # --- v0.5: lifecycle lookup and well-formedness (transactions.md §6) ---
    ("lifecycle: last in list order instead of the greatest from_height",
     "if entry_scheme == scheme_id and best < from_height <= height:",
     "if entry_scheme == scheme_id and from_height <= height:"),
    ("lifecycle: malformed list not refused",
     "self.lifecycle = check_lifecycle(lifecycle)", "self.lifecycle = tuple(lifecycle)"),
    ("lifecycle: unknown scheme allowed in the list",
     'if scheme_id not in SCHEMES:\n            raise ValueError("lifecycle entry for an unknown scheme")',
     "if False:\n            pass"),
    ("lifecycle: equal from_height allowed",
     "if prev_height is not None and from_height <= prev_height:",
     "if prev_height is not None and from_height < prev_height:"),
    ("lifecycle: height order not checked",
     "if prev_height is not None and from_height <= prev_height:", "if False:"),
    ("lifecycle: repeated state (or ACTIVE) allowed",
     "if _STATE_RANK[state] <= _STATE_RANK[prev_state]:", "if _STATE_RANK[state] < _STATE_RANK[prev_state]:"),
    ("lifecycle: states may move backwards",
     "if _STATE_RANK[state] <= _STATE_RANK[prev_state]:", "if False:"),
    ("lifecycle: genesis list (1, ACTIVE, 0), (2, ACTIVE, 0) as in upgrades.md §4",
     "GENESIS_LIFECYCLE = ()", "GENESIS_LIFECYCLE = ((1, ACTIVE, 0), (2, ACTIVE, 0))"),
    # --- v0.5: path 2 is mandatory where it applies (transactions.md §8.2) ---
    ("mandatory path 2: not enforced",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if False:\n            raise"),
    ("mandatory path 2: only path-0 witnesses rejected (path 1 allowed)",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if w.path == 0 and (o.scheme_id, o.commitment) in authorized:\n            raise"),
    ("mandatory path 2: only path-1 witnesses rejected (path 0 allowed)",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if w.path == 1 and (o.scheme_id, o.commitment) in authorized:\n            raise"),
    ("mandatory path 2: only keys selected by path-0 inputs count",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if (o.scheme_id, o.commitment) in {(c.output.scheme_id, c.output.commitment)"
     " for c, ww in zip(coins[:idx], tx.witnesses[:idx]) if ww.path == 0}:\n            raise"),
    ("mandatory path 2: compared with earlier outputs' primary keys, not their selected keys",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if (o.scheme_id, o.commitment) in {(c.output.scheme_id, c.output.commitment)"
     " for c, ww in zip(coins[:idx], tx.witnesses[:idx]) if ww.path in (0, 1)}:\n            raise"),
    ("mandatory path 2: matched on commitment only",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if o.commitment in {c for _s, c in authorized}:\n            raise"),
    ("mandatory path 2: matched on scheme only",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if o.scheme_id in {s for s, _c in authorized}:\n            raise"),
    ("mandatory path 2: also applied to a path-1 input's recovery key",
     "        if (o.scheme_id, o.commitment) in authorized:\n            raise",
     "        if (o.scheme_id, o.commitment) in authorized or (w.path == 1 and"
     " (o.recovery_scheme_id, o.recovery_commitment) in authorized):\n            raise"),
]


def build(old, new):
    if SOURCE.count(old) != 1:
        raise SystemExit("mutation text not unique or missing: %r (%d)" % (old, SOURCE.count(old)))
    module = types.ModuleType("varve_verify_mutant")
    module.__file__ = os.path.join(HERE, "varve_verify.py")
    exec(compile(SOURCE.replace(old, new), module.__file__, "exec"), module.__dict__)
    return module


def run_with(module):
    rv.v = module
    rv.R = rv.Report()
    verifier = module.load_verifier()
    with contextlib.redirect_stdout(io.StringIO()):
        for check in (rv.check_subsidy, rv.check_difficulty, rv.check_addresses, rv.check_params,
                      rv.check_genesis, rv.check_consensus):
            check()
        rv.check_signatures(verifier)
        rv.check_chain(verifier)
    return rv.R.mismatches


def selftest_with(module):
    """Run selftest.py against a mutant; return its failure count."""
    st.v = module
    st.FAILURES = []
    verifier = module.load_verifier()
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            st.test_weight_and_structure(verifier)
            st.test_mtp(verifier)
            st.test_spends(verifier)
            st.test_lifecycle(verifier)
        except Exception as e:  # a crash also counts as detection
            st.FAILURES.append("crashed: %s" % type(e).__name__)
    return len(st.FAILURES)


def main():
    survivors = []
    for name, old, new in MUTATIONS:
        try:
            killed = run_with(build(old, new))
        except Exception as e:  # a crash also counts as detection
            killed = 1
            name += " (crashed: %s)" % type(e).__name__
        print("%-8s %s" % ("killed" if killed else "SURVIVED", name))
        if not killed:
            survivors.append((name, selftest_with(build(old, new))))
    print("\n%d mutations, %d survived the vectors" % (len(MUTATIONS), len(survivors)))
    for s, caught in survivors:
        print("  survivor: %s  [selftest: %s]" % (s, "caught" if caught else "NOT caught"))


if __name__ == "__main__":
    main()

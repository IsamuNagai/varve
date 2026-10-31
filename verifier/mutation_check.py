"""Vector coverage probe: break one rule at a time in varve_verify and report
which mutations the shipped test vectors fail to detect ("survivors").

A survivor is a consensus rule (or boundary) that the vectors do not pin down.
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
     "if self.recovery_scheme_id not in SCHEMES:", "if False:"),
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
    ("path-1 check by scheme state ignored (primary scheme used)",
     "scheme, commitment = o.recovery_scheme_id, o.recovery_commitment",
     "scheme, commitment = o.scheme_id, o.commitment"),
    ("ASERT: truncation instead of floor for negative exponent",
     "exponent = ((parent_time - t0) - TARGET_SPACING * parent_height) * 65536 // ASERT_TAU",
     "_n = ((parent_time - t0) - TARGET_SPACING * parent_height) * 65536\n"
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
            survivors.append(name)
    print("\n%d mutations, %d survived" % (len(MUTATIONS), len(survivors)))
    for s in survivors:
        print("  survivor: " + s)


if __name__ == "__main__":
    main()

"""Tests for verify_public_track_v5.py (V5_SPEC §3). Usage: python3 -B test_v5.py <public_root>
Unit: contract_day for every status and both equalities. Synthetic: bridge_day on hand-built packs (real V4 formulas) — exact
range passes; wrong range, extra UNREVEALED outside the range, wrong chain head, tampered link, declaration after the pack and
no declaration all refuse. Real tree (read-only): the 2026-10-07 pack bridges with the signed outage document and its final chain
equals the 2026-10-08 seam; without the document or with a shifted range it does not."""
import gzip, hashlib, importlib.util, json, shutil, struct, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUB = Path(sys.argv[1])
OPENSSL, COSIGN, OTS = (Path(shutil.which(n) or n) for n in ('openssl', 'cosign', 'ots'))
spec = importlib.util.spec_from_file_location('v5', HERE / 'verify_public_track_v5.py'); v5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(v5)
v4 = v5.load_v4(PUB)
results = {}

# 1. contract_day
D, DL = '2026-10-21', 1_000_000
cases = [(('2026-10-20', 0, 0, DL, True), ('V4.1', 'ON_TIME', False)), (('2026-10-20', 1, 0, DL, True), ('V4.1', 'LATE_PACK', True)),
         (('2026-10-20', None, 0, DL, False), ('V4.1', 'MISSING_PACK', True)), ((D, 0, 0, DL, True), ('V4.2', 'ON_TIME', False)),
         ((D, -5, 0, DL, True), ('V4.2', 'ON_TIME', False)), ((D, 3600, 0, DL, True), ('V4.2', 'LATE_RESTORED', False)),
         ((D, 86400, 0, DL, True), ('V4.2', 'LATE_RESTORED', False)), ((D, 86401, 0, DL, True), ('V4.2', 'LATE_FINAL_PENALTY', True)),
         ((D, None, DL + 10, DL, False), ('V4.2', 'LATE_PENDING', False)), ((D, None, DL + 86399, DL, False), ('V4.2', 'LATE_PENDING', False)),
         ((D, None, DL + 86400, DL, False), ('V4.2', 'LATE_FINAL_PENALTY', True))]
for args, want in cases:
    got = v5.contract_day(args[0], args[1], args[2], args[3], admitted=args[4])
    assert got == want, (args, got, want)
results['contract_day_cases'] = len(cases)


# 2. synthetic bridge_day
def build_pack(root, tokens, gap, head, tamper=None):
    rows, chain = [], bytes.fromhex(head)
    for t in tokens:
        if t in gap:
            rows.append({'token_id': t, 'opening_status': 'UNREVEALED', 'public_score': 'MISS'}); continue
        claim = {'schema': 'proof-tape-public-claim-v2', 'epoch': 'PT', 'token_id': t, 'source_time_utc': 'x', 'issued_time_utc': 'y',
                 'claim_kind': 'NO_SIGNAL', 'direction_if_signal': None}
        salt = hashlib.sha256(b'salt%d' % t).digest()
        leaf = hashlib.sha256(v4.PUB_LEAF + salt + v4.canonical(claim)).digest()
        chain = hashlib.sha256(v4.PUB_CHAIN + chain + struct.pack('>Q', t) + leaf).digest()
        rows.append({'token_id': t, 'opening_status': 'OPENED', 'public_claim': claim, 'public_salt_hex': salt.hex(),
                     'public_leaf_sha256': leaf.hex(), 'public_chain_sha256': chain.hex()})
    if tamper is not None:
        rows[tamper]['public_chain_sha256'] = '00' * 32
    path = Path(root) / 'pack.jsonl.gz'
    with gzip.open(path, 'wt') as f:
        for r in rows: f.write(json.dumps(r) + '\n')
    return {'pack': {'path': 'pack.jsonl.gz'}, 'previous_public_chain_sha256': head}, chain.hex()


head = 'ab' * 32
tokens = list(range(100, 120)); gap = set(range(103, 108))
outage = {'path': 'amendments/X.json', 'sha256': 'f' * 64, 'first': 103, 'end_exclusive': 108, 'external_epoch': 50, 'incident_id': 'T'}
refused = lambda r: r[0] is None and 'refused' in r[1]
kw = dict(seam_known=True, previous_last_opened=True)
with tempfile.TemporaryDirectory() as tmp:
    m, final = build_pack(tmp, tokens, gap, head)
    rows = list(v4.iter_jsonl_gzip(Path(tmp) / 'pack.jsonl.gz'))
    before_gap = [r for r in rows if r['token_id'] == 102][0]['public_chain_sha256']
    good = dict(outage, previous_chain=before_gap)
    got, info = v5.bridge_day(v4, Path(tmp), m, 100, [good], **kw)
    assert got == final and info['tokens_bridged'] == 5, (got, info)
    assert v5.bridge_day(v4, Path(tmp), m, 50, [good], **kw)[0] == final, 'equal external times are accepted'
    assert refused(v5.bridge_day(v4, Path(tmp), m, 100, [], **kw)), 'no declaration'
    assert refused(v5.bridge_day(v4, Path(tmp), m, 100, [dict(good, first=104)], **kw)), 'shifted range'
    assert refused(v5.bridge_day(v4, Path(tmp), m, 100, [dict(good, end_exclusive=109)], **kw)), 'wider range'
    assert refused(v5.bridge_day(v4, Path(tmp), m, 10, [good], **kw)), 'declaration anchored after the pack'
    try:
        v5.bridge_day(v4, Path(tmp), m, 100, [dict(good, previous_chain='cd' * 32)], **kw); raise SystemExit('wrong head accepted')
    except v4.AuditFailure:
        pass
    m2, _ = build_pack(tmp, tokens, gap, head, tamper=12)
    try:
        v5.bridge_day(v4, Path(tmp), m2, 100, [good], **kw); raise SystemExit('tampered link accepted')
    except v4.AuditFailure:
        pass
    m3, _ = build_pack(tmp, tokens, gap | {115}, head)
    assert refused(v5.bridge_day(v4, Path(tmp), m3, 100, [good], **kw)), 'extra unrevealed outside the range'
    # ranges touching the day boundaries
    m4, final4 = build_pack(tmp, tokens, set(range(100, 104)), head)  # outage starts at the pack's first token
    at_start = dict(outage, first=100, end_exclusive=104, previous_chain=head)
    assert v5.bridge_day(v4, Path(tmp), m4, 100, [at_start], **kw)[0] == final4, 'range at the day start with a verified predecessor'
    assert refused(v5.bridge_day(v4, Path(tmp), m4, 100, [at_start], seam_known=False, previous_last_opened=True)), 'unverified seam'
    assert refused(v5.bridge_day(v4, Path(tmp), m4, 100, [at_start], seam_known=True, previous_last_opened=False)), 'previous token not opened'
    assert refused(v5.bridge_day(v4, Path(tmp), m4, 100, [dict(at_start, first=99)], **kw)), 'range extended into the previous day'
    m5, _ = build_pack(tmp, tokens, set(range(115, 120)), head)  # outage reaching the pack's end
    assert refused(v5.bridge_day(v4, Path(tmp), m5, 100, [dict(outage, first=115, end_exclusive=120, previous_chain='00' * 32)], **kw)), 'first token after the range in the next day'
    assert refused(v5.bridge_day(v4, Path(tmp), m5, 100, [dict(outage, first=115, end_exclusive=125, previous_chain='00' * 32)], **kw)), 'range extended into the following day'
    m6, _ = build_pack(tmp, tokens, set(tokens), head)  # all-gap day
    assert refused(v5.bridge_day(v4, Path(tmp), m6, 100, [dict(outage, first=100, end_exclusive=120, previous_chain=head)], **kw)), 'all-gap day'
results['bridge_synthetic_cases'] = 17

# 3. real tree, read-only: 2026-10-07 → 2026-10-08
core, _ = v4.core_contract(PUB, openssl=OPENSSL, cosign=COSIGN, ots=OTS)
outages = v5.declared_outages(v4, PUB, core, OPENSSL, COSIGN, 10 ** 12)
assert len(outages) == 1 and (outages[0]['first'], outages[0]['end_exclusive']) == (89566560, 89567677), outages
m7 = json.loads((PUB / 'manifests/FULL_TOKEN_PACK_2026-10-07.json').read_text())
m8 = json.loads((PUB / 'manifests/FULL_TOKEN_PACK_2026-10-08.json').read_text())
ext7 = v4.sigstore_time(PUB / 'manifests/FULL_TOKEN_PACK_2026-10-07.json', COSIGN, core['cosign_public_key'])
kw = dict(seam_known=True, previous_last_opened=True)
final7, info7 = v5.bridge_day(v4, PUB, m7, ext7, outages, **kw)
assert final7 == m8['previous_public_chain_sha256'] and info7['tokens_bridged'] == 1117, (final7, info7)
assert refused(v5.bridge_day(v4, PUB, m7, ext7, [], **kw))
assert refused(v5.bridge_day(v4, PUB, m7, ext7, [dict(outages[0], first=89566561)], **kw))
assert refused(v5.bridge_day(v4, PUB, m7, ext7, [dict(outages[0], first=89566559)], **kw)), 'Codex F2: extended to the opened 89566559'
results['real_tree_10_07_bridge'] = {'final_chain_equals_10_08_seam': True, 'tokens_bridged': 1117, 'without_document': 'NOT_BRIDGED',
                                     'shifted_range': 'NOT_BRIDGED', 'extended_into_opened_89566559': 'NOT_BRIDGED'}

# 4. evidence pre-check (Codex R2 F3): nothing missing on the real tree; one removed hour file is reported as unavailable evidence
import os
genesis_epoch = (int(core['genesis']['starts_after_token']) + 1) * 20
manifests = sorted(p for p in (PUB / 'manifests').glob('FULL_TOKEN_PACK_????-??-??.json'))
assert all(v5.missing_evidence(PUB, json.loads(m.read_text()), m, genesis_epoch) == [] for m in manifests), 'real tree must be complete'
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    m7p = PUB / 'manifests/FULL_TOKEN_PACK_2026-10-07.json'; doc7 = json.loads(m7p.read_text())
    wanted = set()
    for rel in [str(m7p.relative_to(PUB)) + s for s in ('', '.sig', '.ots')] + [doc7['pack']['path']]:
        wanted.add(rel)
    probe = v5.missing_evidence(Path('/nonexistent'), doc7, Path('/nonexistent/manifests/FULL_TOKEN_PACK_2026-10-07.json'), genesis_epoch)
    wanted |= set(probe)  # with an empty root every referenced file is "missing": this lists them all
    for rel in wanted:
        src, dst = PUB / rel, root / rel
        if src.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True); os.symlink(src, dst)
    local = root / 'manifests/FULL_TOKEN_PACK_2026-10-07.json'
    assert v5.missing_evidence(root, doc7, local, genesis_epoch) == [], 'symlinked copy complete'
    (root / 'hours/20261007_06.json').unlink()
    gone = v5.missing_evidence(root, doc7, local, genesis_epoch)
    assert gone == ['hours/20261007_06.json'], gone
results['evidence_precheck'] = {'real_manifests_checked': len(manifests), 'missing_on_real_tree': 0,
                                'removed_hour_reported_as_unavailable': 'hours/20261007_06.json'}
print(json.dumps({'verdict': 'PASS', **results}, sort_keys=True))

"""Scenario tests of verify_public_track_v5.main() with a fake V4 (no cryptography). Covers Codex review F1–F4:
per-figure A/C statuses and exit codes; pending, unanchored and after-as-of packs; demonstrated invalid vs unavailable evidence;
no cascade after missing/invalid days; one penalty per day; V4.2 restoration window and its boundaries; authentication of the
V4.2 amendment, metrics document and this verifier's own release (missing → rehearsal; wrong / bad / late → HOLD).
Usage: python3 -B test_v5_flow.py"""
import contextlib, hashlib, importlib.util, io, json, subprocess, sys, tempfile, types
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
V5_PATH = HERE / 'verify_public_track_v5.py'
SELF_SHA = hashlib.sha256(V5_PATH.read_bytes()).hexdigest()
day_end = lambda d: datetime.fromisoformat(d + 'T00:00:00+00:00').timestamp() + 86400
deadline = lambda d: int(day_end(d) + 96 * 3600 + 600)
EFFECTIVE = int(datetime(2026, 10, 21, tzinfo=timezone.utc).timestamp())


def load_v5():
    spec = importlib.util.spec_from_file_location('v5', V5_PATH); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def run(days, now, *, packs, rules='official', diag=None, tape=True):
    """days: list of day strings; packs: {day: behaviour} with behaviour in
    ('ok', late_seconds:int, 'missing', 'unanchored', 'invalid', 'unavailable', ('after', seconds_after_now))."""
    v5 = load_v5(); diag = diag or {}
    fake = types.SimpleNamespace()
    fake.AuditFailure = type('AuditFailure', (RuntimeError,), {})
    fake.utc = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()
    fake.official_tokens_in_day = lambda day, official_from: 4320
    fake.valid_sha256_hex = lambda v: isinstance(v, str) and len(v) == 64
    fake.sha256 = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    fake.verify_content_hash = lambda payload: payload.get('content_sha256') == 'ok'
    fake.CANONICAL_MANIFEST, fake.EVIDENCE_CONTRACT, fake.DEADLINE_CLARIFICATION = 'CANON.json', 'V4.json', 'V41.json'
    def core_contract_failing(root, **k):
        raise v5.ToolFailure('cosign could not run')
    fake.core_contract = lambda root, **k: ({'genesis': {'starts_after_token': 0, 'public_genesis_chain_sha256': 'aa' * 32},
                                             'manifest': {'official_from_token': 0, 'track_id': 'TEST'}, 'public_key': 'k', 'cosign_public_key': 'c'}, {})
    fake.due_days = lambda start, n: [{'day': d, 'deadline_epoch': deadline(d), 'deadline_utc': fake.utc(deadline(d))} for d in days if deadline(d) <= n]

    def verify_ed25519(path, key, openssl):
        if json.loads(Path(path).read_text()).get('BAD_SIG'):
            raise subprocess.CalledProcessError(1, 'openssl')
    fake.verify_ed25519 = verify_ed25519

    def sigstore_time(path, cosign, key):
        doc = json.loads(Path(path).read_text())
        if '_ext' in doc:
            return doc['_ext']
        d = path.stem[-10:]; b = packs.get(d, 'ok')
        if isinstance(b, tuple) and b[0] == 'after':
            return int(now + b[1])
        return deadline(d) + (b if isinstance(b, int) else -60)
    fake.sigstore_time = sigstore_time

    def verify_pack(path, *, previous_chain, expected_day, **k):
        b = packs.get(expected_day, 'ok')
        if b == 'tool_failure':
            raise v5.ToolFailure('openssl ts -verify failed and its known-good control does not pass')
        if b == 'invalid':
            raise fake.AuditFailure('public leaf mismatch')
        if b == 'unavailable':
            raise FileNotFoundError('witness file missing from the public tree')
        manifest = json.loads(path.read_text())
        if previous_chain != manifest['previous_public_chain_sha256']:
            raise fake.AuditFailure('cross-pack public-chain seam mismatch')
        return {'status': 'ON_TIME_COMPLETE', 'manifest': manifest, 'final_chain': manifest['final'], 'unrevealed_tokens': [],
                'signal_rows': [], 'trusted_time_by_token': {}, 'rows': [{'opening_status': 'OPENED'}]}
    fake.verify_pack = verify_pack
    calls = []

    def score_rows(results, *, official_from, tape):
        calls.append(len(calls))
        which = 'C' if len(calls) == 1 else 'A'
        penalties = sum(4320 for r in results if r.get('full_day_penalty'))
        d = diag.get(which, {})
        return {'score': {'hits': 0, 'misses': penalties, 'denominator': penalties, 'hit_rate': 0.0},
                'unrevealed_or_missing_pack_misses': penalties, 'insufficient_tape_tokens': d.get('insufficient', []),
                'rejudge_mismatches': d.get('mismatch', []), 'legacy_judge_differences': [], 'timing_misses': 0, 'unresolved_or_expired_misses': 0}
    fake.score_rows = score_rows
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); (root / 'manifests').mkdir(); (root / 'amendments').mkdir(); (root / 'tape').mkdir()
        (root / 'tape' / 'x.zip').write_bytes(b'tape')
        fake.load_binance_closes = lambda p: {'_files': [root / 'tape' / 'x.zip']}
        chain = 'aa' * 32
        for i, d in enumerate(days):
            nxt = ('%02x' % (i + 1)) * 32
            b = packs.get(d, 'ok')
            if b != 'missing':
                ymd = d.replace('-', ''); prev = datetime.fromisoformat(d + 'T00:00:00+00:00').timestamp() - 300
                pymd = datetime.fromtimestamp(prev, timezone.utc).strftime('%Y%m%d')
                mp = root / 'manifests' / f'FULL_TOKEN_PACK_{d}.json'
                mp.write_text(json.dumps({'previous_public_chain_sha256': chain, 'final': nxt, 'day_utc': d,
                                          'pack': {'path': f'packs/{d}.jsonl.gz'},
                                          'five_minute_witnesses': [{'identifier': f'{ymd}_0000', 'artifact': f'witnesses/{ymd}_0000.json'}]}))
                files = [f'manifests/FULL_TOKEN_PACK_{d}.json.sig', f'manifests/FULL_TOKEN_PACK_{d}.json.ots', f'packs/{d}.jsonl.gz',
                         f'witnesses/{ymd}_0000.json', f'witnesses/{ymd}_0000.json.sig', f'witnesses/{ymd}_0000.json.sigstore.json',
                         f'witnesses/{pymd}_2355.json', f'hours/{ymd}_00.json.sig', f'hours/{ymd}_00.json.sigstore.json',
                         f'hours/{ymd}_00.json.ots', f'hours/{pymd}_23.json'] + ([] if b == 'missing_hour' else [f'hours/{ymd}_00.json'])
                for f in files:
                    (root / f).parent.mkdir(parents=True, exist_ok=True); (root / f).write_text('{}')
                if b != 'unanchored':
                    (root / 'manifests' / f'FULL_TOKEN_PACK_{d}.json.sigstore.json').write_text('{}')
            chain = nxt
        for name in ('CANON.json', 'V4.json', 'V41.json'):
            (root / 'amendments' / name).write_text(json.dumps({'name': name}))
        sha = lambda n: hashlib.sha256((root / 'amendments' / n).read_bytes()).hexdigest()
        scope = {'track_id': 'OTHER-TRACK' if rules == 'wrong_track' else 'TEST',
                 'canonical_track_manifest_sha256': ('2' * 64) if rules == 'wrong_canonical' else sha('CANON.json')}
        if rules != 'none':
            base_ext = int(now) + 100 if rules == 'after_asof' else min(EFFECTIVE - 3600, int(now) - 3600)  # anchored before as-of
            def doc(name, payload, ext=None, bad=False):
                ext = base_ext if ext is None else ext
                p = root / 'amendments' / name
                p.write_text(json.dumps({**payload, 'content_sha256': 'ok', '_ext': ext, **({'BAD_SIG': True} if bad else {})}))
                (root / 'amendments' / (name + '.sigstore.json')).write_text('{}')
                return hashlib.sha256(p.read_bytes()).hexdigest()
            a = doc('PROOF_TAPE_EVIDENCE_CONTRACT_V4_2_X.json', {**scope, 'schema': 'proof-tape-evidence-contract-amendment-v1',
                     'amends_contract_sha256': ('3' * 64) if rules == 'wrong_amends' else sha('V4.json'), 'amends_clarification_sha256': sha('V41.json'),
                     'scoring_effective_for_official_days_from_utc': '2026-10-22T00:00:00Z' if rules == 'wrong_date' else '2026-10-21T00:00:00Z',
                     'scoring_effective_from_token': 89627040, 'full_pack_timing': {'restoration_window_seconds': 86400}},
                    ext=EFFECTIVE + 60 if rules == 'late_anchor' else None, bad=rules == 'bad_sig')
            mt = doc('PUBLIC_METRICS_V5_X.json', {**scope, 'schema': 'laniakea-public-metrics-definition-v1'})
            if rules != 'no_release':
                doc('PUBLIC_VERIFIER_RELEASE_V5_X.json', {**scope, 'schema': 'laniakea-public-verifier-release-v1',
                    'files': {'verifier': {'sha256': ('0' * 64) if rules == 'wrong_code' else SELF_SHA}},
                    'imports_unchanged_release': {'sha256': '8e13ba9b13844aa482f6c8b2e2cc2ca3bf73737b78099ae527971d95ff38577c'},
                    'rules_documents': {'amendment': {'sha256': a}, 'metrics': {'sha256': ('1' * 64) if rules == 'wrong_metrics' else mt}}})
        if packs.get('_startup') == 'tool_failure':
            fake.core_contract = core_contract_failing
        v5.load_v4 = lambda public_root: fake
        v5.declared_outages = lambda *a: []
        argv = ['v5', '--public-root', str(root), '--now-epoch', str(now), '--openssl', '/bin/sh', '--cosign', '/bin/sh', '--ots', '/bin/sh']
        if tape:
            argv += ['--binance-tape', str(root / 'tape')]
        sys.argv = argv
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = v5.main()
        return json.loads(out.getvalue()), rc


def st(r):
    return {d['day']: d['status'] for d in r['days']}


checks = []
def check(name, cond):
    assert cond, name
    checks.append(name)


OLD = ['2026-10-01', '2026-10-02', '2026-10-03']
NEW = ['2026-10-21', '2026-10-22', '2026-10-23']
N_OLD = deadline('2026-10-03') + 10
N_NEW = deadline('2026-10-23') + 10

r, rc = run(OLD, N_OLD, packs={})
r2, rc2 = run(OLD, N_OLD, packs={}, rules='after_asof')
check('F4 rule documents anchored after the evaluation instant: not admitted, UNRELEASED_REHEARSAL', r2['verdict'] == 'UNRELEASED_REHEARSAL' and rc2 == 2)
check('baseline official: PASS, exit 0, A/C FINAL', r['verdict'] == 'PASS' and rc == 0 and r['figures']['A_signal_hit']['status'] == 'FINAL' and r['figures']['C_contract_score']['status'] == 'FINAL')
r, rc = run(OLD, N_OLD, packs={'2026-10-02': 30}, diag={'A': {'insufficient': [1]}})
check('F1 A-only insufficient tape on a late V4.1 day: A HOLD, market HOLD, exit 1', r['figures']['A_signal_hit']['status'] == 'HOLD' and r['statuses']['INDEPENDENT_MARKET_REJUDGE'] == 'HOLD' and r['verdict'] == 'HOLD' and rc == 1)
r, rc = run(OLD, N_OLD, packs={}, diag={'A': {'mismatch': [1]}})
check('F1 A-only rejudge mismatch: HOLD, exit 1', r['figures']['A_signal_hit']['status'] == 'HOLD' and r['verdict'] == 'HOLD' and rc == 1)
r, rc = run(OLD, N_OLD, packs={}, diag={'C': {'insufficient': [1]}})
check('F1 C market HOLD: C HOLD, exit 1', r['figures']['C_contract_score']['status'] == 'HOLD' and r['verdict'] == 'HOLD' and rc == 1)
r, rc = run(NEW, N_NEW, packs={'2026-10-23': 'missing'})
check('F1/F3 last due V4.2 day missing inside the window with tape: LATE_PENDING, PROVISIONAL, exit 2',
      st(r)['2026-10-23'] == 'LATE_PENDING' and r['figures']['A_signal_hit']['status'] == 'PROVISIONAL' and r['verdict'] == 'PROVISIONAL' and rc == 2)
r, rc = run(OLD, N_OLD, packs={'2026-10-03': 'missing'})
check('F1 missing last V4.1 day: MISSING_PACK penalty, integrity HOLD, exit 1',
      st(r)['2026-10-03'] == 'MISSING_PACK' and r['statuses']['CRYPTOGRAPHIC_INTEGRITY'] == 'HOLD' and rc == 1 and r['figures']['C_contract_score']['penalty_days'] == ['2026-10-03'])
r, rc = run(OLD, N_OLD, packs={'2026-10-02': 'missing'})
check('F1 unverified predecessor: later day ON_TIME, seam UNVERIFIED, no penalty, HOLD',
      st(r)['2026-10-03'] == 'ON_TIME' and [d for d in r['days'] if d['day'] == '2026-10-03'][0]['seam'] == 'UNVERIFIED_PREDECESSOR_UNAVAILABLE'
      and r['figures']['C_contract_score']['penalty_days'] == ['2026-10-02'] and r['verdict'] == 'HOLD')
r, rc = run(NEW, N_NEW, packs={'2026-10-23': 'unanchored'})
check('F3 manifest present, bundle pending inside the window: LATE_PENDING, no penalty', st(r)['2026-10-23'] == 'LATE_PENDING' and not r['figures']['C_contract_score']['penalty_days'])
r, rc = run(NEW, N_NEW, packs={'2026-10-23': ('after', 3600)})
check('F3 verified anchor after as-of (V4.2): LATE_PENDING, not LATE_RESTORED', st(r)['2026-10-23'] == 'LATE_PENDING')
r, rc = run(OLD, N_OLD, packs={'2026-10-03': ('after', 3600)})
check('F3 verified anchor after as-of (V4.1): MISSING_PACK', st(r)['2026-10-03'] == 'MISSING_PACK')
r, rc = run(NEW, deadline('2026-10-23'), packs={'2026-10-23': 0})
check('F3 as-of exactly at the original deadline, stamp at the deadline: ON_TIME', st(r)['2026-10-23'] == 'ON_TIME')
r, rc = run(NEW, deadline('2026-10-23') + 86400, packs={'2026-10-23': 'missing'})
check('F3 as-of exactly at the hard deadline, no pack: LATE_FINAL_PENALTY', st(r)['2026-10-23'] == 'LATE_FINAL_PENALTY')
r, rc = run(NEW, deadline('2026-10-23') + 86399, packs={'2026-10-23': 'missing'})
check('F3 one second before the hard deadline: LATE_PENDING', st(r)['2026-10-23'] == 'LATE_PENDING')
r, rc = run(OLD, N_OLD, packs={'2026-10-02': 'invalid'})
check('F3 demonstrated bad bytes: INVALID_PACK with penalty; next day not penalized', st(r)['2026-10-02'] == 'INVALID_PACK' and r['figures']['C_contract_score']['penalty_days'] == ['2026-10-02'])
r, rc = run(OLD, N_OLD, packs={'2026-10-02': 'unavailable'})
check('F3 unavailable evidence: EVIDENCE_UNAVAILABLE, no penalty, HOLD', st(r)['2026-10-02'] == 'EVIDENCE_UNAVAILABLE' and not r['figures']['C_contract_score']['penalty_days'] and r['verdict'] == 'HOLD')
r, rc = run(NEW, N_NEW + 86400 * 2, packs={'2026-10-21': 3600, '2026-10-22': 90000})
check('V4.2 late 1 h restored without penalty; late 25 h final penalty; one penalty per day',
      st(r)['2026-10-21'] == 'LATE_RESTORED' and st(r)['2026-10-22'] == 'LATE_FINAL_PENALTY' and r['figures']['C_contract_score']['penalty_days'] == ['2026-10-22'])
r, rc = run(OLD, N_OLD, packs={}, rules='none')
check('F4 rules absent: UNRELEASED_REHEARSAL, exit 2', r['verdict'] == 'UNRELEASED_REHEARSAL' and rc == 2 and r['figures']['C_contract_score']['status'] == 'UNRELEASED_REHEARSAL')
r, rc = run(OLD, N_OLD, packs={}, rules='no_release')
check('F4 release missing: UNRELEASED_REHEARSAL', r['verdict'] == 'UNRELEASED_REHEARSAL' and rc == 2)
for bad in ('wrong_code', 'wrong_metrics', 'bad_sig', 'late_anchor', 'wrong_date'):
    r, rc = run(NEW, N_NEW, packs={}, rules=bad)  # evaluated after 2026-10-21, so a late prospective anchor is visible
    check(f'F4 {bad}: HOLD, exit 1', r['verdict'] == 'HOLD' and rc == 1 and r['rules_authentication']['mode'] == 'HOLD')
r, rc = run(OLD, N_OLD, packs={'2026-10-02': 'missing_hour'})
check('R2-F3 a referenced hour file missing: EVIDENCE_UNAVAILABLE, no penalty, HOLD (never PASS)',
      st(r)['2026-10-02'] == 'EVIDENCE_UNAVAILABLE' and not r['figures']['C_contract_score']['penalty_days'] and r['verdict'] == 'HOLD' and rc == 1)
for bad in ('wrong_track', 'wrong_canonical', 'wrong_amends'):
    r, rc = run(NEW, N_NEW, packs={}, rules=bad)
    check(f'R2-F4 {bad}: rules HOLD, exit 1', r['rules_authentication']['mode'] == 'HOLD' and r['verdict'] == 'HOLD' and rc == 1)
r, rc = run(OLD, N_OLD, packs={'2026-10-02': 'tool_failure'})
check('R3-F3 tool failure inside pack verification: EVIDENCE_UNAVAILABLE, no penalty, HOLD, exit 1',
      st(r)['2026-10-02'] == 'EVIDENCE_UNAVAILABLE' and not r['figures']['C_contract_score']['penalty_days'] and r['verdict'] == 'HOLD' and rc == 1)
r, rc = run(OLD, N_OLD, packs={'_startup': 'tool_failure'})
check('R3-F3 tool failure at startup: HOLD VERIFIER_TOOL_FAILURE, exit 1', r['verdict'] == 'HOLD' and r.get('reason') == 'VERIFIER_TOOL_FAILURE' and rc == 1)
r, rc = run(OLD, N_OLD, packs={}, tape=False)
check('no tape: market pending, PROVISIONAL, exit 2', r['statuses']['INDEPENDENT_MARKET_REJUDGE'] == 'PENDING_PUBLIC_BINANCE_TAPE' and r['verdict'] == 'PROVISIONAL' and rc == 2)
cov = r['figures']['B_coverage']
check('B categories disjoint and sum to expected', sum(v for k, v in cov.items() if k.endswith('_tokens') and k != 'expected_official_tokens') == cov['expected_official_tokens'])
print(json.dumps({'verdict': 'PASS', 'scenarios': len(checks), 'checks': checks}, ensure_ascii=False))

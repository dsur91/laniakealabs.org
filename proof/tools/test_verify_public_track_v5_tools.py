"""Tool and I/O failure tests for V5 (Codex reviews R3 and R4, plus my own red-team passes). Usage: python3 -B test_v5_tools.py <public_root>
Rule under test: a failure becomes a penalty only when every input was readable, the tool positively attributed the failure to the
evidence and the same-format known-good control passes; anything else is a ToolFailure (HOLD, no penalty, no FINAL).
Unit (scripted subprocess): process failures on the first try and on the retry, no control, failing control, missing evidence
marker, I/O marker, unreadable input, rc 0 without the success marker with and without a healthy control, informational OTS,
renamed binary, unknown kinds fail closed, bundle formats, unreadable bundle, control that cannot be saved, ts -reply.
Real tools on the real 2026-10-05 pack (226 signals) and on copies: broken openssl → ToolFailure, 0 fabricated misses; a receipt reused
for another leaf (real «message imprint mismatch») → exactly one timing miss, also as the first receipt with the warm-up; ENOSPC or
a read-only directory while staging RFC 3161 files after the warm-up → ToolFailure, 0 misses; unreadable TSA root → ToolFailure;
unreadable signature / bundle / blob / .ots copy with a healthy control → ToolFailure; still rejected: flipped Ed25519 signature,
tampered blob, moved integratedTime, flipped message signature, response hash mismatch, garbage .ots."""
import base64, contextlib, errno, importlib.util, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUB = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('v5', HERE / 'verify_public_track_v5.py'); v5 = importlib.util.module_from_spec(spec); spec.loader.exec_module(v5)
results, cases = {}, {}
TMP = Path(tempfile.mkdtemp(prefix='v5-tools-test-'))
MARKS = 'Signature Verified Successfully\nVerification: OK\nTime stamp: Oct  5 00:00:00 2026 GMT\nVerified OK'


class FakeReal:
    """A stand-in for the subprocess module: a script of outcomes per call; ('ok',) prints every success marker."""
    TimeoutExpired, CalledProcessError, CompletedProcess = subprocess.TimeoutExpired, subprocess.CalledProcessError, subprocess.CompletedProcess

    def __init__(self, outcomes):
        self.outcomes = list(outcomes); self.calls = []

    def run(self, cmd, *a, **k):
        self.calls.append(cmd)
        o = self.outcomes.pop(0) if self.outcomes else ('ok',)
        if o[0] == 'oserror':
            raise FileNotFoundError('no such tool')
        if o[0] == 'timeout':
            raise subprocess.TimeoutExpired(cmd, 1)
        rc = {'ok': 0, 'fail': 1, 'signal': -9}[o[0]]
        return subprocess.CompletedProcess(cmd, rc, MARKS if len(o) == 1 and rc == 0 else (o[1] if len(o) > 1 else ''), '')


def outcome(guard, cmd, **k):
    """'tool_failure', 'called_process_error' or the return code."""
    try:
        return guard.run(cmd, **k).returncode
    except v5.ToolFailure:
        return 'tool_failure'
    except subprocess.CalledProcessError:
        return 'called_process_error'


DATA = TMP / 'data.json'; DATA.write_text('{}')
PK = ['openssl', 'pkeyutl', '-verify', '-in', str(DATA)]
TS = ['openssl', 'ts', '-verify', '-digest', 'ab', '-in', str(DATA)]
TR = ['openssl', 'ts', '-reply', '-in', str(DATA), '-text']
UP = ['ots', 'upgrade', 'x.ots']
BAD_SIG, IMPRINT, INVALID = 'Signature Verification Failure', 'error:ts_check_imprints:message imprint mismatch', 'Error: invalid signature'
G = lambda outcomes, **k: v5.ToolGuard(FakeReal(outcomes), **k)
g = G([('oserror',)]); cases['cannot start → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
g = G([('signal',)]); cases['killed by a signal → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
g = G([('fail', BAD_SIG), ('fail', BAD_SIG)]); cases['evidence marker but no control yet → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
g = G([('ok',), ('fail', BAD_SIG), ('fail', BAD_SIG), ('fail', BAD_SIG)]); g.run(PK, check=True)
cases['control fails too → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
g = G([('ok',), ('fail', BAD_SIG), ('fail', BAD_SIG), ('ok',)]); g.run(PK, check=True)
cases['readable input + evidence marker + control passes → V4 rule (CalledProcessError)'] = outcome(g, PK, check=True) == 'called_process_error'
g = G([('ok',), ('fail', ''), ('fail', ''), ('ok',)]); g.run(PK, check=True)
cases['no evidence marker, control passes → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
g = G([('ok',), ('fail', BAD_SIG + '\nPermission denied'), ('fail', BAD_SIG + '\nPermission denied'), ('ok',)]); g.run(PK, check=True)
cases['evidence marker together with an I/O error → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
LOCKED = TMP / 'locked.sig'; LOCKED.write_text('x'); os.chmod(LOCKED, 0)
g = G([('ok',), ('fail', BAD_SIG), ('fail', BAD_SIG), ('ok',)]); g.run(PK, check=True)
cases['evidence marker but an input is unreadable → ToolFailure'] = outcome(g, PK + ['-sigfile', str(LOCKED)], check=True) == 'tool_failure'
os.chmod(LOCKED, 0o600)
g = G([('fail',), ('ok',)]); cases['retry success'] = outcome(g, PK, check=True) == 0
g = G([('ok',), ('fail', BAD_SIG), ('timeout',)]); g.run(PK, check=True)
cases['retry times out → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
g = G([('ok',), ('fail', BAD_SIG), ('signal',)]); g.run(PK, check=True)
cases['retry killed by a signal → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
g = G([('fail', 'calendar unreachable')]); cases['informational non-zero passes'] = outcome(g, UP, check=False) == 1
g = G([('timeout',)]); cases['informational timeout is not a verdict'] = outcome(g, UP, check=False, text=True) == 1
g = G([('signal',)]); cases['informational signal is not a verdict'] = outcome(g, UP, check=False) == -9
for name, cmd in (('ts -verify', TS), ('pkeyutl', PK), ('cosign', ['cosign', 'verify-blob', str(DATA)])):
    g = G([('ok', ''), ('ok', '')]); cases[f'{name} rc 0 without its marker, no control → ToolFailure'] = outcome(g, cmd, check=True) == 'tool_failure'
    g = G([('ok',), ('ok', ''), ('ok', ''), ('ok',)]); g.run(cmd, check=True)
    cases[f'{name} rc 0 without its marker, healthy control → ToolFailure'] = outcome(g, cmd, check=True) == 'tool_failure'
g = G([('ok',), ('fail', IMPRINT), ('fail', IMPRINT), ('ok',)]); g.run(TR, check=True)
cases['ts -reply failure is never attributed'] = outcome(g, TR, check=True) == 'tool_failure'
RENAMED = ['/x/openssl3', 'ts', '-verify', '-digest', 'ab', '-in', str(DATA)]
g = G([('ok', ''), ('ok', '')], roles={'/x/openssl3': 'openssl'})
cases['renamed binary keeps its role and marker check'] = g.kind(RENAMED) == ('openssl', 'ts', '-verify') and outcome(g, RENAMED, check=True) == 'tool_failure'
g = G([('ok',), ('fail', BAD_SIG), ('fail', BAD_SIG), ('ok',)]); g.run(['openssl', 'dgst', str(DATA)], check=True)
cases['unknown command kind is never attributed'] = outcome(g, ['openssl', 'dgst', str(DATA)], check=True) == 'tool_failure'


def bundle(name, media):
    path = TMP / name
    path.write_text(json.dumps({'mediaType': media, 'verificationMaterial': {'tlogEntries': [{'kindVersion': {'kind': 'hashedrekord', 'version': '0.0.1'}}]}}))
    return str(path)


V03, V09 = 'application/vnd.dev.sigstore.bundle.v0.3+json', 'application/vnd.dev.sigstore.bundle.v0.9+json'
a1, a2, b1 = bundle('a1.json', V03), bundle('a2.json', V03), bundle('b1.json', V09)
junk = TMP / 'junk.json'; junk.write_text('not a bundle')
CO = lambda b: ['cosign', 'verify-blob', '--bundle', b, str(DATA)]
g = G([('ok',), ('fail', INVALID), ('fail', INVALID), ('ok',)]); g.run(CO(a1), check=False)
cases['same bundle format, evidence marker, control passes → genuine (rc 1 to V4)'] = outcome(g, CO(a2), check=False) == 1
g = G([('ok',), ('fail', INVALID), ('fail', INVALID)]); g.run(CO(a1), check=False)
cases['bundle format never verified in this run → ToolFailure'] = outcome(g, CO(b1), check=False) == 'tool_failure'
g = G([('ok',), ('fail', INVALID), ('fail', INVALID), ('ok',)]); g.run(CO(a1), check=False)
cases['unparseable bundle with an evidence marker is attributable'] = outcome(g, CO(str(junk)), check=False) == 1
os.chmod(a2, 0)
g = G([('ok',)]); g.run(CO(a1), check=False)
cases['unreadable bundle → ToolFailure, not «unparseable»'] = outcome(g, CO(a2), check=False) == 'tool_failure'
os.chmod(a2, 0o600)
g = G([('ok',)]); os.chmod(g.control_dir, 0o500)
cases['a control that cannot be saved → ToolFailure'] = outcome(g, PK, check=True) == 'tool_failure'
os.chmod(g.control_dir, 0o700)
failed = [name for name, ok in cases.items() if not ok]
assert not failed, failed
results['unit_cases'] = len(cases)

# ---------------- real tools ----------------
OPENSSL, COSIGN, OTS = (Path(shutil.which(n) or n) for n in ('openssl', 'cosign', 'ots'))
ROLES = {OPENSSL: 'openssl', COSIGN: 'cosign', OTS: 'ots'}
v4 = v5.load_v4(PUB)
v5.install_io_adapters(v4)
core, _ = v4.core_contract(PUB, openssl=OPENSSL, cosign=COSIGN, ots=OTS)
manifest_path = PUB / 'manifests/FULL_TOKEN_PACK_2026-10-05.json'
m5 = json.loads(manifest_path.read_text())
rows = list(v4.iter_jsonl_gzip(PUB / m5['pack']['path']))
signals = [r for r in rows if r.get('opening_status') == 'OPENED' and r['public_claim']['claim_kind'] == 'SIGNAL']
assert len(signals) == 226, len(signals)
token_of = {r['public_leaf_sha256']: int(r['token_id']) for r in signals}
previous = m5['previous_public_chain_sha256']


class Swap:
    """Real subprocess; for one target leaf, `openssl ts -verify` is asked about another leaf's digest — a receipt reused for the
    wrong claim, so the real tool reports a real «message imprint mismatch». Mode 'broken' fails every receipt without any reason."""
    TimeoutExpired, CalledProcessError, CompletedProcess = subprocess.TimeoutExpired, subprocess.CalledProcessError, subprocess.CompletedProcess

    def __init__(self, target=None, broken=False):
        self.target, self.broken = target, broken

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def run(self, cmd, *a, **k):
        if [Path(str(cmd[0])).name] + [str(x) for x in cmd[1:3]] == ['openssl', 'ts', '-verify']:
            if self.broken:
                return subprocess.CompletedProcess(cmd, 1, b'Verification: FAILED', b'')
            i = cmd.index('-digest') + 1
            if str(cmd[i]) == self.target:
                other = signals[0 if self.target != signals[0]['public_leaf_sha256'] else 1]['public_leaf_sha256']
                cmd = list(cmd); cmd[i] = other
        return subprocess.run(cmd, *a, **k)


def guarded(real, warm=True):
    guard = v5.ToolGuard(real, roles=ROLES)
    v4.subprocess = guard
    w = v5.warm_up_timestamp_controls(v4, guard, PUB, core, OPENSSL) if warm else None
    return guard, w


def verify_day():
    return v4.verify_pack(manifest_path, public_root=PUB, core=core, openssl=OPENSSL, cosign=COSIGN, ots=OTS, expected_day='2026-10-05',
                          deadline_epoch=v5.NO_DEADLINE, previous_chain=previous, witness_cache={}, hour_cache={})


def expect_tool_failure(label):
    try:
        r = verify_day()
        raise SystemExit(f'{label}: verify_pack returned {len(r["invalid_timing_tokens"])} timing misses instead of ToolFailure')
    except v5.ToolFailure as error:
        return str(error)[:140]


guard, _ = guarded(Swap(broken=True), warm=False)
results['broken_openssl_all_receipts'] = expect_tool_failure('broken openssl')
target = signals[10]['public_leaf_sha256']
guard, warm = guarded(Swap(target=target))
r = verify_day(); assert r['invalid_timing_tokens'] == [token_of[target]], r['invalid_timing_tokens'][:5]
results['receipt_reused_for_another_leaf'] = {'invalid_timing_tokens': 1, 'token': token_of[target], 'warm_up': warm['status']}
first = signals[0]['public_leaf_sha256']
guarded(Swap(target=first), warm=False)
results['first_receipt_reused_without_warm_up'] = expect_tool_failure('first receipt without warm-up')
guard, warm = guarded(Swap(target=first))
r = verify_day(); assert r['invalid_timing_tokens'] == [token_of[first]], r['invalid_timing_tokens'][:5]
assert [e['event'] for e in guard.events if e['phase'] == 'verification'] == ['genuine verification failure (inputs readable, evidence-failure marker, control passes)'], guard.events
results['first_receipt_reused_with_warm_up'] = {'invalid_timing_tokens': 1, 'token': token_of[first], 'warm_up': warm}

# Codex R4 case 1: staging I/O after a successful warm-up
real_tempdir = v4.tempfile.TemporaryDirectory


@contextlib.contextmanager
def read_only_tempdir(*a, **k):
    with real_tempdir(*a, **k) as d:
        os.chmod(d, 0o500)
        try:
            yield d
        finally:
            os.chmod(d, 0o700)


def enospc_tempdir(*a, **k):
    if k.get('prefix') == 'public-track-tsa-':
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    return real_tempdir(*a, **k)


for label, factory in (('ENOSPC creating the RFC 3161 staging directory', enospc_tempdir), ('read-only RFC 3161 staging directory', read_only_tempdir)):
    guard, warm = guarded(subprocess)
    assert warm['status'] == 'ESTABLISHED', warm
    v4.tempfile.TemporaryDirectory = factory
    try:
        results[label] = expect_tool_failure(label)
    finally:
        v4.tempfile.TemporaryDirectory = real_tempdir

# unreadable TSA root inside V4's swallowing block (hashed there with sha256(trusted_root))
guard, warm = guarded(subprocess)
root_copy = TMP / 'SIGSTORE_TSA_TRUSTED_ROOT.json'; root_copy.write_bytes(Path(core['tsa_trusted_root']).read_bytes())
saved_root = core['tsa_trusted_root']; core['tsa_trusted_root'] = root_copy; os.chmod(root_copy, 0)
try:
    results['unreadable TSA root'] = expect_tool_failure('unreadable TSA root')
finally:
    os.chmod(root_copy, 0o600); core['tsa_trusted_root'] = saved_root

# response hash mismatch in memory (file bytes and their sha unchanged) → V4's own content check: exactly one timing miss
real_iter = v4.iter_jsonl_gzip
victim = signals[20]['public_leaf_sha256']


def tampered_rows(path):
    for row in real_iter(path):
        if row.get('public_leaf_sha256') == victim:
            row = json.loads(json.dumps(row)); row['private_rfc3161']['response_sha256'] = '0' * 64
        yield row


guard, warm = guarded(subprocess)
v4.iter_jsonl_gzip = tampered_rows
try:
    r = verify_day(); assert r['invalid_timing_tokens'] == [token_of[victim]], r['invalid_timing_tokens'][:5]
finally:
    v4.iter_jsonl_gzip = real_iter
results['response_hash_mismatch'] = {'invalid_timing_tokens': 1, 'token': token_of[victim]}

# copies: unreadable inputs with a healthy control → ToolFailure; tampered evidence → still rejected
C = TMP / 'copies'; C.mkdir()
for name in ('m.json', 'm.json.sig', 'm.json.sigstore.json', 'm.json.ots'):
    (C / name).write_bytes((PUB / 'manifests' / ('FULL_TOKEN_PACK_2026-10-05.json' + name[6:])).read_bytes())
guard, _ = guarded(subprocess, warm=False)
v4.verify_ed25519(C / 'm.json', core['public_key'], OPENSSL)  # control
v4.sigstore_time(C / 'm.json', COSIGN, core['cosign_public_key'])  # control
v4.ots_receipt_info(C / 'm.json', OTS)  # control
copy_cases = {}
for label, name, call in (('unreadable signature', 'm.json.sig', lambda: v4.verify_ed25519(C / 'm.json', core['public_key'], OPENSSL)),
                          ('unreadable bundle', 'm.json.sigstore.json', lambda: v4.sigstore_time(C / 'm.json', COSIGN, core['cosign_public_key'])),
                          ('unreadable blob', 'm.json', lambda: v4.sigstore_time(C / 'm.json', COSIGN, core['cosign_public_key'])),
                          ('unreadable .ots', 'm.json.ots', lambda: v4.ots_receipt_info(C / 'm.json', OTS))):
    os.chmod(C / name, 0)
    try:
        call(); copy_cases[label] = 'NOT REJECTED'
    except v5.ToolFailure:
        copy_cases[label] = 'ToolFailure'
    except Exception as error:
        copy_cases[label] = f'WRONG {type(error).__name__}: {str(error)[:80]}'
    finally:
        os.chmod(C / name, 0o600)


def flip(raw, i=5):
    b = bytearray(raw); b[i] ^= 1; return bytes(b)


(C / 't_m.json').write_bytes((C / 'm.json').read_bytes()); (C / 't_m.json.sig').write_bytes(flip((C / 'm.json.sig').read_bytes()))
try:
    v4.verify_ed25519(C / 't_m.json', core['public_key'], OPENSSL); copy_cases['flipped Ed25519 signature'] = 'NOT REJECTED'
except v5.ToolFailure as error:
    copy_cases['flipped Ed25519 signature'] = f'WRONG ToolFailure: {str(error)[:100]}'
except subprocess.CalledProcessError:
    copy_cases['flipped Ed25519 signature'] = 'CalledProcessError'
bundle_doc = json.loads((C / 'm.json.sigstore.json').read_text())


def bundle_case(label, mutate_doc=None, blob=None):
    d = C / label.replace(' ', '_'); d.mkdir()
    (d / 'm.json').write_bytes(blob if blob is not None else (C / 'm.json').read_bytes())
    doc = json.loads(json.dumps(bundle_doc))
    if mutate_doc:
        mutate_doc(doc)
    (d / 'm.json.sigstore.json').write_text(json.dumps(doc))
    try:
        v4.sigstore_time(d / 'm.json', COSIGN, core['cosign_public_key']); copy_cases[label] = 'NOT REJECTED'
    except v5.ToolFailure as error:
        copy_cases[label] = f'WRONG ToolFailure: {str(error)[:100]}'
    except Exception as error:
        copy_cases[label] = type(error).__name__ if type(error).__name__ == 'AuditFailure' else f'WRONG {type(error).__name__}'


def move_time(doc):
    e = doc['verificationMaterial']['tlogEntries'][0]; e['integratedTime'] = str(int(e['integratedTime']) - 3600)


def flip_message_signature(doc):
    s = doc['messageSignature']; s['signature'] = base64.b64encode(flip(base64.b64decode(s['signature']), 10)).decode()


bundle_case('tampered blob', blob=(C / 'm.json').read_bytes() + b' ')
bundle_case('moved integratedTime', move_time)
bundle_case('flipped message signature', flip_message_signature)
(C / 'g.json').write_text('{}'); (C / 'g.json.ots').write_bytes(b'garbage')
try:
    v4.ots_receipt_info(C / 'g.json', OTS); copy_cases['garbage .ots'] = 'NOT REJECTED'
except v5.ToolFailure as error:
    copy_cases['garbage .ots'] = f'WRONG ToolFailure: {str(error)[:100]}'
except Exception as error:
    copy_cases['garbage .ots'] = type(error).__name__ if type(error).__name__ == 'AuditFailure' else f'WRONG {type(error).__name__}'
expected = {'unreadable signature': 'ToolFailure', 'unreadable bundle': 'ToolFailure', 'unreadable blob': 'ToolFailure', 'unreadable .ots': 'ToolFailure',
            'flipped Ed25519 signature': 'CalledProcessError', 'tampered blob': 'AuditFailure', 'moved integratedTime': 'AuditFailure',
            'flipped message signature': 'AuditFailure', 'garbage .ots': 'AuditFailure'}
assert copy_cases == expected, json.dumps(copy_cases, indent=1, ensure_ascii=False)
results['copies'] = copy_cases
v4.subprocess = subprocess
shutil.rmtree(TMP, ignore_errors=True)
print(json.dumps({'verdict': 'PASS', **results}, sort_keys=True, ensure_ascii=False))

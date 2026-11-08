#!/usr/bin/env python3
"""LANIAKEA public track verifier V5.

V4 stays byte-identical and is imported (its sha256 is checked against the released V4) for every cryptographic primitive:
Ed25519, Sigstore, OpenTimestamps, RFC 3161, witness chains, full pack verification and the issued-first-trade judge.
V5 changes only what V4 cannot do, and publishes three separately labelled figures with their own diagnostics:
1. A late pack is fully verified instead of being skipped (contract V4: late opening
   «MAY_RESTORE_AUDIT_CONTENT_BUT_NEVER_REDUCES_THE_FROZEN_PENALTY»); its own penalty is kept; the next seam uses its final chain.
2. A declared outage is crossed only through an authenticated signed outage document whose whole range lies inside one pack,
   every token of the range UNREVEALED, the token before the range OPENED with the document's chain head, the first token after
   the range OPENED and every later link recomputed. Cross-day ranges are refused (integrity HOLD), never guessed.
3. Evidence is judged as of --now-epoch: a pack counts only if its verified Sigstore time is not after the evaluation instant.
   Unavailable evidence (no bundle yet, a missing public file, a missing tool) is never turned into a penalty: it is pending
   or HOLD. Only demonstrated invalid bytes or signatures are INVALID_PACK.
4. A missing / invalid / unbridgeable predecessor never cascades into penalties for a later verified day: that seam is reported
   UNVERIFIED and integrity stays HOLD.
5. Contract version per day: V4.1 before 2026-10-21; V4.2 from 2026-10-21 (late ≤ 24 h → LATE_RESTORED, scored by content and
   flagged; no admitted pack while as-of < deadline + 24 h → LATE_PENDING, not final; otherwise LATE_FINAL_PENALTY). V4.2, the
   metrics definition and this verifier's own release are authenticated (Ed25519, Sigstore, sha binding, prospective anchor,
   effective date); without them the run is an explicit UNRELEASED_REHEARSAL, never an official result.
Figures: A signal hit, B coverage (disjoint categories, sums to expected), C contract score. Exit 0 only for an official,
final PASS; 1 HOLD; 2 provisional or unreleased."""

import argparse
import atexit
import base64
import copy
import os
import tempfile
import threading
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

V4_RELEASED_SHA256 = "8e13ba9b13844aa482f6c8b2e2cc2ca3bf73737b78099ae527971d95ff38577c"
V42_FIRST_DAY = "2026-10-21"
V42_FIRST_TOKEN = 89627040
V42_EFFECTIVE_EPOCH = int(datetime(2026, 10, 21, tzinfo=timezone.utc).timestamp())
RESTORE_SECONDS = 86400
NO_DEADLINE = 10 ** 12
OUTAGE_SCHEMA = "proof-tape-declared-inference-outage-closed-v1"
RULE_DOCUMENTS = {
    "amendment": ("PROOF_TAPE_EVIDENCE_CONTRACT_V4_2_*.json", "proof-tape-evidence-contract-amendment-v1"),
    "metrics": ("PUBLIC_METRICS_V5_*.json", "laniakea-public-metrics-definition-v1"),
    "release": ("PUBLIC_VERIFIER_RELEASE_V5_*.json", "laniakea-public-verifier-release-v1"),
}
EXIT = {"PASS": 0, "HOLD": 1}  # every other verdict (PROVISIONAL, UNRELEASED_REHEARSAL) exits 2


class EvidenceUnavailable(RuntimeError):
    """Required evidence or tooling is not available; never a reason to penalize."""


class ToolFailure(BaseException):
    """A verification tool did not run, or is not trustworthy right now. A BaseException on purpose: V4's `except Exception`
    blocks (for example the RFC 3161 check that turns any error into a timing miss) cannot swallow it, so a broken tool can never
    become a fabricated miss, an INVALID verdict or a FINAL figure."""


class ToolGuard:
    """Replaces V4's module-level `subprocess` (V4 bytes unchanged). Tools are identified by the configured path (--openssl /
    --cosign / --ots), so a renamed binary is still guarded. Every command except the informational OTS upgrade / verify is
    verdict-bearing (fail-closed): success needs return code 0 and, where the tool prints one, its success marker. The first
    successful call of each command kind is remembered as a known-good control (inputs copied, since V4 deletes its temporary
    files; a failure to save it is a ToolFailure). On a failure: one retry; the failure is attributed to the evidence only if
    (a) every path argument is fully readable, (b) the tool printed a positive evidence-failure marker for that command and no
    I/O error, and (c) the same-format known-good control passes now — then V4's own rule applies. Anything else (unreadable
    input, I/O error, no marker, rc 0 without the success marker, absent or failing control) → ToolFailure (HOLD, no penalty).
    Process-level failures on any attempt (cannot start, signal, timeout) → ToolFailure, never attributed to the input. A control counts only for the same input format (Sigstore bundle media type and log entry
    kind): a tool that verified one bundle format has not shown it can verify another, so a format it never verified in this run
    cannot be blamed on the evidence (ToolFailure); an unparseable bundle is invalid for every tool and stays attributable.
    Informational commands keep their non-zero results (pending, not a verdict)."""

    INFORMATIONAL = {("ots", "upgrade"), ("ots", "verify")}
    FAILURE_MARKERS = {  # the tool itself attributes the failure to the evidence (probed on the real tools, R5_PLAN.md)
        ("openssl", "pkeyutl"): ("signature verification failure",),
        ("openssl", "ts", "-verify"): ("message imprint mismatch", "signature failure", "asn1 encoding routines", "certificate verify error"),
        ("openssl", "ts", "-reply"): (),  # runs after a successful -verify on the same bytes: any failure is the tool's
        ("cosign", "verify-blob"): ("failed to verify signature", "failed to verify log inclusion", "invalid signature"),
        ("ots", "info"): ("is not a timestamp file",),
    }
    IO_MARKERS = ("permission denied", "no such file", "can't open", "could not open", "error loading", "bio_new_file", "system library",
                  "system lib", "no space left", "input/output error", "too many open files", "malloc failure", "cannot allocate",
                  "new-bundle-format", "i/o timeout", "read-only file system", "is a directory", "errno")
    MARKERS = {("openssl", "pkeyutl"): "Signature Verified Successfully", ("openssl", "ts", "-verify"): "Verification: OK",
               ("openssl", "ts", "-reply"): "Time stamp:", ("cosign", "verify-blob"): "Verified OK"}

    def __init__(self, real, roles=None):
        self.real, self.lock, self.known_good, self.events, self.phase = real, threading.Lock(), {}, [], "verification"
        self.roles = {str(path): role for path, role in (roles or {}).items()}
        self.control_dir = Path(tempfile.mkdtemp(prefix="v5-tool-controls-"))
        atexit.register(shutil.rmtree, self.control_dir, True)

    def __getattr__(self, name):
        return getattr(self.real, name)

    def kind(self, cmd):
        role = self.roles.get(str(cmd[0]), Path(str(cmd[0])).name)
        parts = [role] + [str(x) for x in cmd[1:3]]
        if role == "openssl" and len(parts) > 1 and parts[1] == "ts":
            return tuple(parts[:3])
        return tuple(parts[:2])

    def looks_successful(self, kind, result):
        if result.returncode != 0:
            return False
        marker = self.MARKERS.get(kind)
        if marker is None:
            return True
        text = "".join(x if isinstance(x, str) else (x or b"").decode("utf-8", "replace") for x in (result.stdout, result.stderr))
        return marker in text

    @staticmethod
    def variant(kind, cmd):
        if kind != ("cosign", "verify-blob"):
            return None
        args = list(map(str, cmd))
        if "--bundle" not in args or args.index("--bundle") + 1 >= len(args):
            return "unparseable"
        try:
            raw = Path(args[args.index("--bundle") + 1]).read_bytes()
        except OSError as error:
            raise ToolFailure(f"cosign bundle unreadable: {type(error).__name__}: {error}") from error
        try:
            bundle = json.loads(raw.decode("utf-8"))
            entry = ((bundle.get("verificationMaterial") or {}).get("tlogEntries") or [{}])[0]
            version = entry.get("kindVersion") or {}
            return f"{bundle.get('mediaType')} {version.get('kind')} {version.get('version')}"
        except (ValueError, AttributeError, TypeError, IndexError, KeyError):
            return "unparseable"

    def note(self, kind, event):
        self.events.append({"kind": " ".join(kind), "phase": self.phase, "event": event})

    def remember(self, kind, variant, cmd, kwargs):
        with self.lock:
            if (kind, variant) in self.known_good:
                return
            target = self.control_dir / f"{'_'.join(kind).replace('-', '')}_{len(self.known_good)}"
            control = []
            try:
                target.mkdir(parents=True, exist_ok=True)
                for i, arg in enumerate(cmd):
                    path = Path(str(arg))
                    if i and path.is_file():
                        copy_path = target / f"{i}_{path.name}"
                        copy_path.write_bytes(path.read_bytes())
                        control.append(str(copy_path))
                    else:
                        control.append(str(arg))
            except OSError as error:
                self.note(kind, f"cannot save the known-good control: {type(error).__name__}")
                raise ToolFailure(f"{' '.join(kind)}: cannot save the known-good control: {type(error).__name__}: {error}") from error
            self.known_good[(kind, variant)] = (control, {k: v for k, v in kwargs.items() if k in ("text", "timeout")})

    def control_for(self, kind, variant):
        if variant == "unparseable":
            return next((entry for (k, _), entry in sorted(self.known_good.items(), key=lambda x: str(x[0])) if k == kind), None)
        return self.known_good.get((kind, variant))

    def control_ok(self, kind, variant):
        entry = self.control_for(kind, variant)
        if entry is None:
            return False
        cmd, kwargs = entry
        try:
            result = self.real.run(cmd, check=False, capture_output=True, **kwargs)
        except Exception:
            return False
        return self.looks_successful(kind, result)

    @staticmethod
    def unreadable_inputs(cmd):
        problems = []
        for arg in list(cmd)[1:]:
            text = str(arg)
            if "/" not in text:
                continue
            try:
                with open(text, "rb") as handle:
                    while handle.read(1 << 20):
                        pass
            except OSError as error:
                problems.append(f"{Path(text).name}: {type(error).__name__}")
        return problems

    def unattributable(self, kind, cmd, result):
        """None when the failure is positively attributable to the evidence, else the reason it is not."""
        if result.returncode == 0:
            return "return code 0 without the success marker: indeterminate result"
        unreadable = self.unreadable_inputs(cmd)
        if unreadable:
            return "input not readable: " + ", ".join(unreadable[:3])
        text = "".join(x if isinstance(x, str) else (x or b"").decode("utf-8", "replace") for x in (result.stdout, result.stderr)).lower()
        io = [m for m in self.IO_MARKERS if m in text]
        if io:
            return "the tool reported an I/O or resource error: " + ", ".join(io[:3])
        markers = self.FAILURE_MARKERS.get(kind)
        if not markers or not any(m in text for m in markers):
            return "no positive evidence-failure marker in the tool output"
        return None

    def attempt(self, kind, cmd, args, kwargs):
        """One run. Process-level failures are a ToolFailure for verdict commands and a non-zero result for informational ones."""
        try:
            result = self.real.run(cmd, *args, **{**kwargs, "check": False})
        except (OSError, self.real.TimeoutExpired, ValueError) as error:
            if kind in self.INFORMATIONAL:
                empty = "" if kwargs.get("text") else b""
                note = f"informational tool unavailable: {type(error).__name__}"
                return self.real.CompletedProcess(cmd, 1, empty, note if kwargs.get("text") else note.encode())
            self.note(kind, f"cannot run: {type(error).__name__}")
            raise ToolFailure(f"{' '.join(kind)} could not run: {type(error).__name__}: {error}")
        if result.returncode < 0 and kind not in self.INFORMATIONAL:
            self.note(kind, f"killed by signal {-result.returncode}")
            raise ToolFailure(f"{' '.join(kind)} killed by signal {-result.returncode}")
        return result

    def run(self, cmd, *args, **kwargs):
        kind = self.kind(cmd)
        check = kwargs.get("check", False)
        result = self.attempt(kind, cmd, args, kwargs)
        if kind not in self.INFORMATIONAL:
            variant = self.variant(kind, cmd)
            if self.looks_successful(kind, result):
                self.remember(kind, variant, cmd, kwargs)
            else:
                retry = self.attempt(kind, cmd, args, kwargs)
                if self.looks_successful(kind, retry):
                    self.remember(kind, variant, cmd, kwargs)
                    result = retry
                else:
                    reason = self.unattributable(kind, cmd, retry)
                    if reason is None and not self.control_ok(kind, variant):
                        reason = ("no known-good control exists yet for this input format: a broken or outdated tool and invalid evidence "
                                  "cannot be told apart" if self.control_for(kind, variant) is None
                                  else "its known-good control fails too: tool not trustworthy")
                    if reason is not None:
                        self.note(kind, f"unattributable failure: {reason[:80]}")
                        raise ToolFailure(f"{' '.join(kind)} failed and the failure cannot be attributed to the evidence: {reason}")
                    self.note(kind, "genuine verification failure (inputs readable, evidence-failure marker, control passes)")
                    result = retry
        if check and result.returncode != 0:
            raise self.real.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)
        return result


def install_io_adapters(v4):
    """V4's RFC 3161 check runs inside a broad `except Exception` that turns any error into a timing miss. Its whole operation is
    wrapped (V4 bytes unchanged): only a failure the guard positively attributed to the receipt (CalledProcessError) may reach that
    handler; reading the TSA root, the staging directory and files, the reply parsing and anything else become ToolFailure. V4's
    `sha256(path)` is wrapped too, so an unreadable file (e.g. the TSA root hashed inside the same block) is unavailable evidence,
    never a miss. V4's own content checks (hash, root and signed-time mismatches) raise AuditFailure and keep their effect."""
    if getattr(v4, "_v5_io_adapters", False):
        return
    v4._v5_io_adapters = True
    if hasattr(v4, "sha256"):
        original_sha256 = v4.sha256

        def sha256(path):
            try:
                return original_sha256(path)
            except OSError as error:
                raise ToolFailure(f"cannot read {Path(str(path)).name}: {type(error).__name__}: {error}") from error
        v4.sha256 = sha256
    if hasattr(v4, "verify_rfc3161_leaf"):
        original_rfc3161 = v4.verify_rfc3161_leaf

        def verify_rfc3161_leaf(response, public_leaf, *, openssl, trusted_root):
            try:
                value = original_rfc3161(response, public_leaf, openssl=openssl, trusted_root=trusted_root)
                v4.epoch(value)  # the caller parses it inside the same swallowing block
                return value
            except (ToolFailure, subprocess.CalledProcessError):
                raise
            except Exception as error:
                raise ToolFailure(f"RFC 3161 verification could not complete: {type(error).__name__}: {str(error)[:200]}") from error
        v4.verify_rfc3161_leaf = verify_rfc3161_leaf


def warm_up_timestamp_controls(v4, guard, public_root, core, openssl, limit=20):
    """Give the RFC 3161 commands a known-good control before any verdict, so a genuinely invalid first receipt is judged by V4's
    rule instead of being unattributable. Any receipt that verifies is a valid control (a forged receipt cannot pass), so the order
    chosen by the publisher cannot bias it. Read-only; it changes no verdict."""
    try:
        private_tsa_from = int(core["contract"]["rules"]["TSA_BEFORE_OUTCOME"]["private_rfc3161_required_from_token"])
    except (KeyError, TypeError, ValueError):
        return {"status": "NOT_ESTABLISHED", "receipts_tried": 0, "reason": "contract has no private RFC 3161 rule"}
    guard.phase, tried = "warm-up", 0
    try:
        for manifest_path in sorted((public_root / "manifests").glob("FULL_TOKEN_PACK_*.json")):
            if manifest_path.suffixes != [".json"]:
                continue
            try:
                rows = v4.iter_jsonl_gzip(public_root / str(json.loads(manifest_path.read_text())["pack"]["path"]))
                for row in rows:
                    receipt, claim = row.get("private_rfc3161"), row.get("public_claim") or {}
                    if (row.get("opening_status") != "OPENED" or claim.get("claim_kind") != "SIGNAL" or receipt is None
                            or int(row["token_id"]) < private_tsa_from):
                        continue
                    tried += 1
                    try:
                        v4.verify_rfc3161_leaf(base64.b64decode(receipt["response_der_base64"]), bytes.fromhex(str(row["public_leaf_sha256"])),
                                               openssl=openssl, trusted_root=core["tsa_trusted_root"])
                        return {"status": "ESTABLISHED", "receipts_tried": tried, "control_token": int(row["token_id"])}
                    except (Exception, ToolFailure):
                        if tried >= limit:
                            return {"status": "NOT_ESTABLISHED", "receipts_tried": tried}
            except Exception:
                continue
        return {"status": "NOT_ESTABLISHED", "receipts_tried": tried}
    finally:
        guard.phase = "verification"


def load_v4(public_root: Path):
    path = public_root / "tools" / "verify_public_track_v4.py"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != V4_RELEASED_SHA256:
        raise RuntimeError(f"verify_public_track_v4.py is not the released V4: {digest}")
    spec = importlib.util.spec_from_file_location("verify_public_track_v4", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_public_track_v4"] = module
    spec.loader.exec_module(module)
    return module


def bundle_of(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".sigstore.json")


def stamped_time(v4, path, cosign, cosign_key):
    """Verified Sigstore time of an artifact; EvidenceUnavailable if its bundle is not there (yet)."""
    if not bundle_of(path).is_file():
        raise EvidenceUnavailable(f"Sigstore bundle not available: {bundle_of(path).name}")
    return v4.sigstore_time(path, cosign, cosign_key)


def classify(error):
    """'unavailable' (missing file / tool) or 'invalid' (demonstrated bad bytes, signature or content)."""
    if isinstance(error, (EvidenceUnavailable, FileNotFoundError, PermissionError)):
        return "unavailable"
    if isinstance(error, (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, ValueError, TypeError)) \
            or type(error).__name__ == "AuditFailure":
        return "invalid"  # demonstrated bad signature, bytes or content
    return "unavailable"


def missing_evidence(public_root, manifest, path, genesis_epoch):
    """Every file V4 will read for this pack (manifest signature and OTS, pack file, each witness artifact with its signature and
    bundle and its predecessor, each hour with signature, bundle, OTS and predecessor). V4 reports a missing file as a generic
    AuditFailure, so availability is checked here first: a missing file is unavailable evidence, never proof of corruption."""
    need = [path.with_suffix(".json.sig"), path.with_suffix(".json.ots"), public_root / str(manifest["pack"]["path"])]
    first_witness, first_hour = genesis_epoch // 300 * 300, genesis_epoch // 3600 * 3600
    for row in manifest.get("five_minute_witnesses", []):
        ident = str(row["identifier"])
        art = public_root / str(row["artifact"])
        need += [art, art.with_suffix(".json.sig"), art.with_suffix(".json.sigstore.json")]
        start = int(datetime.strptime(ident, "%Y%m%d_%H%M").replace(tzinfo=timezone.utc).timestamp())
        if start - 300 >= first_witness:
            need.append(public_root / "witnesses" / (datetime.fromtimestamp(start - 300, timezone.utc).strftime("%Y%m%d_%H%M") + ".json"))
        hour = public_root / "hours" / (ident[:11] + ".json")
        need += [hour, hour.with_suffix(".json.sig"), hour.with_suffix(".json.sigstore.json"), hour.with_suffix(".json.ots")]
        if start // 3600 * 3600 - 3600 >= first_hour:
            need.append(public_root / "hours" / (datetime.fromtimestamp(start // 3600 * 3600 - 3600, timezone.utc).strftime("%Y%m%d_%H") + ".json"))
    return sorted({str(p.relative_to(public_root)) for p in need if not p.is_file()})


def authenticate_rules(v4, public_root, core, openssl, cosign, now_epoch, self_sha):
    """OFFICIAL_RELEASED, UNRELEASED_REHEARSAL (documents absent or not yet admitted) or HOLD (present but wrong)."""
    found, reasons, docs = {}, [], {}
    for kind, (pattern, schema) in RULE_DOCUMENTS.items():
        paths = [p for p in sorted((public_root / "amendments").glob(pattern)) if not p.name.endswith(".sigstore.json")]
        if not paths:
            reasons.append(f"{kind} document not published")
            continue
        if len(paths) > 1:
            return {"mode": "HOLD", "reasons": [f"{kind}: more than one document {[p.name for p in paths]}"], "documents": docs}
        path = paths[0]
        try:
            v4.verify_ed25519(path, core["public_key"], openssl)
            external = stamped_time(v4, path, cosign, core["cosign_public_key"])
        except Exception as error:
            if classify(error) == "unavailable":
                reasons.append(f"{kind} not yet anchored: {error}")
                continue
            return {"mode": "HOLD", "reasons": [f"{kind} signature or anchor invalid: {type(error).__name__}"], "documents": docs}
        if external > now_epoch:
            reasons.append(f"{kind} anchored after the evaluation instant")
            continue
        payload = json.loads(path.read_text())
        if payload.get("schema") != schema or not v4.verify_content_hash(payload):
            return {"mode": "HOLD", "reasons": [f"{kind} schema or content hash mismatch"], "documents": docs}
        found[kind] = payload
        docs[kind] = {"path": str(path.relative_to(public_root)), "sha256": v4.sha256(path), "sigstore_utc": v4.utc(external),
                      "external_epoch": external}
    if reasons:
        return {"mode": "UNRELEASED_REHEARSAL", "reasons": reasons, "documents": docs}
    release, amendment = found["release"], found["amendment"]
    canonical_sha = v4.sha256(public_root / "amendments" / v4.CANONICAL_MANIFEST)
    checks = {
        **{f"{kind} belongs to this track": (payload.get("track_id") == core["manifest"]["track_id"]
                                             and payload.get("canonical_track_manifest_sha256") == canonical_sha)
           for kind, payload in found.items()},
        "amendment amends V4": amendment.get("amends_contract_sha256") == v4.sha256(public_root / "amendments" / v4.EVIDENCE_CONTRACT),
        "amendment amends V4.1": amendment.get("amends_clarification_sha256") == v4.sha256(public_root / "amendments" / v4.DEADLINE_CLARIFICATION),
        "release binds this verifier": release.get("files", {}).get("verifier", {}).get("sha256") == self_sha,
        "release binds the unchanged V4": release.get("imports_unchanged_release", {}).get("sha256") == V4_RELEASED_SHA256,
        "release binds the amendment": release.get("rules_documents", {}).get("amendment", {}).get("sha256") == docs["amendment"]["sha256"],
        "release binds the metrics": release.get("rules_documents", {}).get("metrics", {}).get("sha256") == docs["metrics"]["sha256"],
        "effective day": (amendment.get("scoring_effective_for_official_days_from_utc") == V42_FIRST_DAY + "T00:00:00Z"
                          and amendment.get("scoring_effective_from_token") == V42_FIRST_TOKEN),
        "restoration window": amendment.get("full_pack_timing", {}).get("restoration_window_seconds") == RESTORE_SECONDS,
        "prospective anchor": docs["amendment"]["external_epoch"] < V42_EFFECTIVE_EPOCH,
    }
    failed = [name for name, ok in checks.items() if not ok]
    return {"mode": "HOLD" if failed else "OFFICIAL_RELEASED", "reasons": failed, "documents": docs}


def declared_outages(v4, public_root, core, openssl, cosign, now_epoch):
    found = []
    for path in sorted((public_root / "amendments").glob("INFERENCE_OUTAGE_*_CLOSED_*.json")):
        if path.name.endswith(".sigstore.json"):
            continue
        doc = json.loads(path.read_text())
        if doc.get("schema") != OUTAGE_SCHEMA:
            continue
        v4.verify_ed25519(path, core["public_key"], openssl)
        try:
            external = stamped_time(v4, path, cosign, core["cosign_public_key"])
        except EvidenceUnavailable:
            continue  # not yet anchored: not admitted, the bridge will be refused
        if external > now_epoch:
            continue  # not admitted at this evaluation instant
        first, end = int(doc["first_missing_source_token"]), int(doc["missing_source_end_exclusive_token"])
        if (end - first != int(doc["missing_source_token_count"]) or int(doc["last_verified_source_token"]) != first - 1
                or int(doc["first_actual_source_token"]) != end or doc.get("proof_continuation_uses_previous_chain_head") is not True
                or not v4.valid_sha256_hex(doc.get("previous_public_chain_sha256"))):
            raise v4.AuditFailure(f"declared outage document inconsistent: {path.name}")
        found.append({"path": str(path.relative_to(public_root)), "sha256": v4.sha256(path), "first": first, "end_exclusive": end,
                      "previous_chain": str(doc["previous_public_chain_sha256"]), "external_epoch": external,
                      "incident_id": doc.get("incident_id")})
    return found


def bridge_day(v4, public_root, manifest, manifest_external, outages, *, seam_known, previous_last_opened):
    """(final_chain, info) for a verified pack whose only UNREVEALED rows are exactly one declared outage fully inside this pack,
    else (None, {"refused": reason}). Raises AuditFailure on a broken link."""
    rows = list(v4.iter_jsonl_gzip(public_root / manifest["pack"]["path"]))
    tokens = [int(row["token_id"]) for row in rows]
    unrevealed = {int(row["token_id"]) for row in rows if row.get("opening_status") == "UNREVEALED"}
    if not unrevealed:
        return None, {"refused": "no UNREVEALED rows"}
    touching = [o for o in outages if o["first"] <= max(unrevealed) and min(unrevealed) < o["end_exclusive"]]
    if len(touching) != 1:
        return None, {"refused": "UNREVEALED rows not covered by exactly one declared outage"}
    outage = touching[0]
    span = set(range(outage["first"], outage["end_exclusive"]))
    if not span <= set(tokens):
        return None, {"refused": "UNSUPPORTED_CROSS_DAY_OUTAGE: the declared range is not fully inside this pack"}
    if unrevealed != span:
        return None, {"refused": "UNREVEALED rows differ from the declared range"}
    if outage["end_exclusive"] > tokens[-1]:
        return None, {"refused": "UNSUPPORTED_CROSS_DAY_OUTAGE: the first token after the range is not in this pack"}
    if outage["external_epoch"] > manifest_external:
        return None, {"refused": "the outage document was anchored after the pack"}  # equal times are accepted
    opened = {int(row["token_id"]): row for row in rows if row.get("opening_status") == "OPENED"}
    if outage["end_exclusive"] not in opened:
        return None, {"refused": "the first token after the range is not OPENED"}
    if outage["first"] == tokens[0]:
        if not (seam_known and previous_last_opened):
            return None, {"refused": "the token before the range (previous pack) is not verified as OPENED"}
    elif outage["first"] - 1 not in opened:
        return None, {"refused": "the token before the range is not OPENED"}
    chain = bytes.fromhex(str(manifest["previous_public_chain_sha256"]))
    for row in rows:
        token = int(row["token_id"])
        if token in span:
            if token == outage["first"] and chain.hex() != outage["previous_chain"]:
                raise v4.AuditFailure(f"declared outage chain head mismatch before {token}")
            continue
        leaf = hashlib.sha256(v4.PUB_LEAF + bytes.fromhex(str(row["public_salt_hex"])) + v4.canonical(row["public_claim"])).digest()
        if leaf.hex() != row["public_leaf_sha256"]:
            raise v4.AuditFailure(f"public leaf mismatch: {token}")
        chain = hashlib.sha256(v4.PUB_CHAIN + chain + struct.pack(">Q", token) + leaf).digest()
        if chain.hex() != row["public_chain_sha256"]:
            raise v4.AuditFailure(f"public chain mismatch across declared outage: {token}")
    return chain.hex(), {"outage_document": outage["path"], "outage_document_sha256": outage["sha256"],
                         "incident_id": outage["incident_id"], "tokens_bridged": len(span)}


def contract_day(day, late_seconds, now_epoch, deadline_epoch, admitted):
    """(contract_version, status, full_day_penalty) for one due day; admitted = a verified pack stamped by the evaluation instant."""
    version = "V4.2" if day >= V42_FIRST_DAY else "V4.1"
    if not admitted:
        if version == "V4.1":
            return version, "MISSING_PACK", True
        if now_epoch < deadline_epoch + RESTORE_SECONDS:
            return version, "LATE_PENDING", False
        return version, "LATE_FINAL_PENALTY", True
    if late_seconds <= 0:
        return version, "ON_TIME", False
    if version == "V4.1":
        return version, "LATE_PACK", True
    if late_seconds <= RESTORE_SECONDS:
        return version, "LATE_RESTORED", False
    return version, "LATE_FINAL_PENALTY", True


def diagnostics(scored):
    legacy = scored.get("legacy_judge_differences", [])
    direction = sum(1 for d in legacy if (d.get("declared_legacy") or [None])[0] != (d.get("independent_v3") or [None])[0])
    return {"insufficient_tape_tokens": len(scored.get("insufficient_tape_tokens", [])),
            "rejudge_mismatches_current_judge": len(scored.get("rejudge_mismatches", [])),
            "legacy_judge_differences": {"total": len(legacy), "direction": direction, "timing_only": len(legacy) - direction,
                                         "note": "vs legacy pack resolution fields (pre-V3 judge); not prediction errors"},
            "timing_misses": scored.get("timing_misses"), "unresolved_or_expired_misses": scored.get("unresolved_or_expired_misses"),
            "examples": {"insufficient": scored.get("insufficient_tape_tokens", [])[:20], "mismatches": scored.get("rejudge_mismatches", [])[:20]}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--binance-tape", type=Path)
    parser.add_argument("--openssl", type=Path, default=Path(shutil.which("openssl") or "openssl"))
    parser.add_argument("--cosign", type=Path, default=Path(shutil.which("cosign") or "cosign"))
    parser.add_argument("--ots", type=Path, default=Path(shutil.which("ots") or "ots"))
    parser.add_argument("--now-epoch", type=float, default=time.time())
    parser.add_argument("--witness-chain", action="store_true")
    parser.add_argument("--witness-settle-seconds", type=int, default=120)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    started = time.time()
    self_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    missing_tools = [str(t) for t in (args.openssl, args.cosign, args.ots) if not (Path(t).is_file() or shutil.which(str(t)))]
    if missing_tools:
        print(json.dumps({"schema": "laniakea-public-track-verification-v5", "verdict": "HOLD",
                          "reason": "VERIFIER_ENVIRONMENT_UNAVAILABLE", "missing_tools": missing_tools}, indent=2))
        return EXIT["HOLD"]
    v4 = load_v4(args.public_root)
    guard = ToolGuard(subprocess, roles={args.openssl: "openssl", args.cosign: "cosign", args.ots: "ots"})
    v4.subprocess = guard  # every V4 tool call now passes through the guard; V4 bytes are unchanged
    install_io_adapters(v4)
    try:
        return evaluate(v4, guard, args, started, self_sha)
    except ToolFailure as error:
        print(json.dumps({"schema": "laniakea-public-track-verification-v5", "verdict": "HOLD", "reason": "VERIFIER_TOOL_FAILURE",
                          "detail": str(error), "tool_events": guard.events[-20:], "executed_verifier_sha256": self_sha}, indent=2, default=str))
        return EXIT["HOLD"]


def evaluate(v4, guard, args, started, self_sha):
    core, core_evidence = v4.core_contract(args.public_root, openssl=args.openssl, cosign=args.cosign, ots=args.ots)
    warm_up = warm_up_timestamp_controls(v4, guard, args.public_root, core, args.openssl)
    genesis = core["genesis"]
    official_from = int(core["manifest"]["official_from_token"])
    witness_chain = {"status": "NOT_REQUESTED"}
    if args.witness_chain:
        witness_chain = v4.verify_witness_chains(
            args.public_root, now_epoch=args.now_epoch, settle_seconds=args.witness_settle_seconds, workers=args.workers,
            public_key=core["public_key"], cosign=args.cosign, cosign_public_key=core["cosign_public_key"],
            openssl=args.openssl, ots=args.ots)
    rules = authenticate_rules(v4, args.public_root, core, args.openssl, args.cosign, args.now_epoch, self_sha)
    outages = declared_outages(v4, args.public_root, core, args.openssl, args.cosign, args.now_epoch)
    days = v4.due_days(int(genesis["starts_after_token"]), args.now_epoch)
    genesis_epoch = (int(genesis["starts_after_token"]) + 1) * 20
    previous_chain, previous_last_opened = str(genesis["public_genesis_chain_sha256"]), True
    witness_cache, hour_cache = {}, {}
    per_day, contract_results, signal_results, integrity_failures = [], [], [], []
    coverage = {"expected_official_tokens": 0, "revealed_official_tokens": 0, "declared_outage_tokens": 0,
                "unrevealed_undeclared_tokens": 0, "missing_or_invalid_pack_tokens": 0, "pending_tokens": 0,
                "evidence_unavailable_tokens": 0}
    for due in days:
        day, deadline = str(due["day"]), int(due["deadline_epoch"])
        official = v4.official_tokens_in_day(day, official_from)
        coverage["expected_official_tokens"] += official
        path = args.public_root / "manifests" / f"FULL_TOKEN_PACK_{day}.json"
        row = {"day": day, "deadline_utc": due["deadline_utc"], "official_tokens": official}
        seam_known = previous_chain != "UNRECOMPUTABLE"
        admitted, result, external, problem = False, None, None, None
        if path.is_file() and not bundle_of(path).is_file():
            problem = ("not_admitted", "pack manifest present, Sigstore bundle not yet available")
        elif path.is_file():
            try:
                external = stamped_time(v4, path, args.cosign, core["cosign_public_key"])
                if external <= args.now_epoch:
                    manifest_doc = json.loads(path.read_text())
                    absent = missing_evidence(args.public_root, manifest_doc, path, genesis_epoch)
                    if absent:
                        raise EvidenceUnavailable(f"{len(absent)} referenced files missing, e.g. {absent[:3]}")
                    start = previous_chain if seam_known else str(manifest_doc["previous_public_chain_sha256"])
                    result = v4.verify_pack(path, public_root=args.public_root, core=core, openssl=args.openssl, cosign=args.cosign,
                                            ots=args.ots, expected_day=day, deadline_epoch=NO_DEADLINE, previous_chain=start,
                                            witness_cache=witness_cache, hour_cache=hour_cache)
                    admitted = True
                else:
                    problem = ("not_admitted", "Sigstore time after the evaluation instant")
            except ToolFailure as error:
                problem = ("unavailable", f"verification tool failure: {str(error)[:300]}")
            except Exception as error:
                problem = (classify(error), f"{type(error).__name__}: {str(error)[:300]}")
        if problem and problem[0] == "invalid":
            version = "V4.2" if day >= V42_FIRST_DAY else "V4.1"
            row.update(contract_version=version, status="INVALID_PACK", full_day_penalty=True, error=problem[1])
            integrity_failures.append(f"{day}: {problem[1]}")
            coverage["missing_or_invalid_pack_tokens"] += official
            contract_results.append({"full_day_penalty": True, "manifest": {"day_utc": day}})
            per_day.append(row); previous_chain, previous_last_opened = "UNRECOMPUTABLE", False
            continue
        if problem and problem[0] == "unavailable":
            row.update(contract_version="V4.2" if day >= V42_FIRST_DAY else "V4.1", status="EVIDENCE_UNAVAILABLE",
                       full_day_penalty=False, error=problem[1])
            integrity_failures.append(f"{day}: evidence unavailable — {problem[1]}")
            coverage["evidence_unavailable_tokens"] += official
            per_day.append(row); previous_chain, previous_last_opened = "UNRECOMPUTABLE", False
            continue
        if not admitted:
            version, status, penalty = contract_day(day, None, args.now_epoch, deadline, admitted=False)
            row.update(contract_version=version, status=status, full_day_penalty=penalty, reason=(problem or (None, "no pack"))[1])
            if status == "LATE_PENDING":
                coverage["pending_tokens"] += official
            else:
                coverage["missing_or_invalid_pack_tokens"] += official
                integrity_failures.append(f"{day}: no admitted pack")
                contract_results.append({"full_day_penalty": True, "manifest": {"day_utc": day}})
            per_day.append(row); previous_chain, previous_last_opened = "UNRECOMPUTABLE", False
            continue
        late = int(external - deadline)
        final_chain, bridge = result.get("final_chain"), None
        if final_chain is None and result["unrevealed_tokens"]:
            final_chain, bridge = bridge_day(v4, args.public_root, result["manifest"], external, outages,
                                             seam_known=seam_known, previous_last_opened=previous_last_opened)
            if final_chain is None:
                integrity_failures.append(f"{day}: declared outage not bridged — {bridge['refused']}")
        version, status, penalty = contract_day(day, late, args.now_epoch, deadline, admitted=True)
        unrevealed_official = sum(1 for t in result["unrevealed_tokens"] if int(t) >= official_from)
        bridged = unrevealed_official if final_chain is not None and bridge and "tokens_bridged" in bridge else 0
        coverage["revealed_official_tokens"] += official - unrevealed_official
        coverage["declared_outage_tokens"] += bridged
        coverage["unrevealed_undeclared_tokens"] += unrevealed_official - bridged
        row.update(contract_version=version, status=status, full_day_penalty=penalty, late_seconds=max(0, late),
                   manifest_sigstore_utc=v4.utc(external), content=result["status"], signals=len(result["signal_rows"]),
                   unrevealed_tokens=len(result["unrevealed_tokens"]), declared_outage_bridge=bridge,
                   seam="PASS" if seam_known else "UNVERIFIED_PREDECESSOR_UNAVAILABLE", chain_continues=final_chain is not None)
        if not seam_known:
            integrity_failures.append(f"{day}: seam not verifiable — predecessor unavailable")
        if final_chain is None and not bridge:
            integrity_failures.append(f"{day}: chain not recomputable")
        contract_results.append({"full_day_penalty": True, "manifest": {"day_utc": day}} if penalty else result)
        signal_view = copy.copy(result)
        signal_view["unrevealed_tokens"] = []  # A counts issued signals only; unrevealed slots are reported in B
        signal_results.append(signal_view)
        per_day.append(row)
        previous_chain = final_chain or "UNRECOMPUTABLE"
        previous_last_opened = bool(result.get("rows")) and result["rows"][-1].get("opening_status") == "OPENED"
    total = sum(v for k, v in coverage.items() if k != "expected_official_tokens")
    if total != coverage["expected_official_tokens"]:
        raise RuntimeError(f"coverage categories do not sum to expected: {coverage}")
    coverage["coverage_percent"] = (round(100 * coverage["revealed_official_tokens"] / coverage["expected_official_tokens"], 3)
                                    if coverage["expected_official_tokens"] else None)
    coverage["formula"] = "revealed_official_tokens / expected_official_tokens; the six categories are disjoint and sum to expected"
    tape = v4.load_binance_closes(args.binance_tape) if args.binance_tape else None
    contract = v4.score_rows(contract_results, official_from=official_from, tape=tape)
    signal = v4.score_rows(signal_results, official_from=official_from,
                           tape=None if tape is None else v4.load_binance_closes(args.binance_tape))
    diag = {"A": diagnostics(signal), "C": diagnostics(contract)}
    integrity = "PASS" if not integrity_failures and witness_chain.get("status") in ("PASS", "NOT_REQUESTED") else "HOLD"
    if tape is None:
        market = "PENDING_PUBLIC_BINANCE_TAPE"
    elif any(d["insufficient_tape_tokens"] or d["rejudge_mismatches_current_judge"] for d in diag.values()):
        market = "HOLD"
    else:
        market = "PASS"
    pending_days = [r["day"] for r in per_day if r["status"] == "LATE_PENDING"]

    def figure_status(d):
        if integrity == "HOLD" or rules["mode"] == "HOLD" or d["insufficient_tape_tokens"] or d["rejudge_mismatches_current_judge"]:
            return "HOLD"
        if tape is None:
            return "PENDING_INDEPENDENT_MARKET_REJUDGE"
        if pending_days:
            return "PROVISIONAL"
        if rules["mode"] != "OFFICIAL_RELEASED":
            return "UNRELEASED_REHEARSAL"
        return "FINAL"

    status_a, status_c = figure_status(diag["A"]), figure_status(diag["C"])
    if "HOLD" in (status_a, status_c) or market == "HOLD":
        verdict = "HOLD"
    elif "PROVISIONAL" in (status_a, status_c) or market != "PASS":
        verdict = "PROVISIONAL"
    elif rules["mode"] != "OFFICIAL_RELEASED":
        verdict = "UNRELEASED_REHEARSAL"
    else:
        verdict = "PASS"
    tape_manifest = None
    if tape is not None:
        tape_manifest = [{"file": Path(p).name, "bytes": Path(p).stat().st_size, "sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest()}
                         for p in tape["_files"]]
    official_days = sum(1 for r in per_day if r["official_tokens"])
    output = {
        "schema": "laniakea-public-track-verification-v5",
        "verdict": verdict,
        "track_id": core["manifest"]["track_id"],
        "as_of_utc": v4.utc(args.now_epoch),
        "executed_verifier_sha256": self_sha,
        "v4_imported_sha256": V4_RELEASED_SHA256,
        "rules_authentication": {k: v for k, v in rules.items() if k != "documents"} | {
            "documents": {k: {x: y for x, y in v.items() if x != "external_epoch"} for k, v in rules["documents"].items()}},
        "statuses": {
            "CRYPTOGRAPHIC_INTEGRITY": integrity,
            "INDEPENDENT_MARKET_REJUDGE": market,
            "PUNCTUALITY": {"late_days": [{"day": r["day"], "late_seconds": r["late_seconds"], "contract_version": r["contract_version"],
                                           "status": r["status"]} for r in per_day if r.get("late_seconds")]},
        },
        "figures": {
            "A_signal_hit": {"status": status_a, "definition": "hits / issued official signals contained in admitted verified packs",
                             "label_before_2026_10_21": "RETROSPECTIVE_V5_METHOD", **signal["score"]},
            "B_coverage": coverage,
            "C_contract_score": {"status": status_c, "rules": "V4.1 before 2026-10-21, V4.2 from 2026-10-21",
                                 "penalty_days": [r["day"] for r in per_day if r.get("full_day_penalty")],
                                 "penalty_misses": contract["unrevealed_or_missing_pack_misses"], **contract["score"]},
            "pending_days_excluded_from_final": pending_days,
        },
        "diagnostics": {"judge_id": "LANIAKEA-ISSUED-FIRST-TRADE-V3", **diag},
        "scope": {"due_days": len(per_day), "official_days": official_days, "prelaunch_days": len(per_day) - official_days},
        "binance_tape": None if tape is None else {"file_count": len(tape_manifest), "files": tape_manifest,
                                                   "event_count": tape.get("event_count")},
        "v4_cascade_fix": "late packs verified and continue the chain; declared outages bridged only by an authenticated signed document fully inside one pack; unavailable predecessors never penalize later days",
        "declared_outages": [{k: v for k, v in o.items() if k != "external_epoch"} for o in outages],
        "days": per_day,
        "witness_chain": witness_chain,
        "integrity_failures": integrity_failures,
        "core_evidence": core_evidence,
        "dependencies": {"private_databases": False, "private_keys": False, "model_or_recipe": False,
                         "external_binaries": [str(args.openssl), str(args.cosign), str(args.ots)]},
        "tool_guard": {"controls": sorted(" ".join(k) + (f" [{v}]" if v else "") for k, v in guard.known_good), "events": guard.events[-50:],
                       "timestamp_control_warm_up": warm_up},
        "duration_seconds": round(time.time() - started, 3),
    }
    print(json.dumps(output, sort_keys=True, indent=2, default=str))
    return EXIT.get(verdict, 2)


if __name__ == "__main__":
    raise SystemExit(main())

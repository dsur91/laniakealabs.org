#!/usr/bin/env python3
"""Independent public verifier for the LANIAKEA Proof Tape.

Inputs are deliberately limited to the published proof tree, published trust
material, and (optionally) public Binance USD-M BTCUSDT aggTrade archives.
No production database, model artifact, recipe, secret key, or private service
module is imported or read.
"""

from __future__ import annotations

import argparse
import base64
import bisect
import csv
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


PUB_LEAF = b"PROOF-TAPE-PUBLIC-LEAF-V2\0"
PUB_CHAIN = b"PROOF-TAPE-PUBLIC-CHAIN-V2\0"
NODE = b"PROOF-TAPE-MERKLE-NODE-V2\0"
SIGNAL_COUNT = b"PROOF-TAPE-SIGNAL-COUNT-V2\0"
TOKEN_SECONDS = 20
PACK_DELAY_SECONDS = 345_600
PUBLICATION_GRACE_SECONDS = 600
MAX_RESOLUTION_SECONDS = 345_600

CANONICAL_MANIFEST = "CANONICAL_TRACK_MANIFEST_20260902.json"
EVIDENCE_CONTRACT = "PROOF_TAPE_EVIDENCE_CONTRACT_V4_20260902.json"
DEADLINE_CLARIFICATION = "PROOF_TAPE_EVIDENCE_CONTRACT_V4_1_20260902.json"
VERIFIER_RELEASE = "PUBLIC_VERIFIER_RELEASE_V2_20260902.json"


class AuditFailure(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(16 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def epoch(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def verify_content_hash(payload: dict[str, object]) -> bool:
    declared = payload.get("content_sha256")
    if not isinstance(declared, str):
        return False
    body = dict(payload)
    body.pop("content_sha256", None)
    return hashlib.sha256(canonical(body)).hexdigest() == declared


def verify_ed25519(path: Path, public_key: Path, openssl: Path) -> None:
    signature = path.with_suffix(path.suffix + ".sig")
    subprocess.run(
        [
            str(openssl),
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public_key),
            "-in",
            str(path),
            "-sigfile",
            str(signature),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )


def sigstore_time(path: Path, cosign: Path, cosign_public_key: Path) -> int:
    bundle = path.with_suffix(path.suffix + ".sigstore.json")
    command = [
        str(cosign),
        "verify-blob",
        "--key",
        str(cosign_public_key),
        "--bundle",
        str(bundle),
        str(path),
    ]
    failure = None
    for attempt in range(3):
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            break
        failure = compact_process_note(result.stderr or result.stdout)
        if attempt < 2:
            time.sleep(0.2 * (attempt + 1))
    else:
        raise AuditFailure(f"Sigstore verification failed after 3 attempts: {failure}")
    payload = json.loads(bundle.read_text())
    values = [
        int(row["integratedTime"])
        for row in payload["verificationMaterial"].get("tlogEntries", [])
    ]
    if not values:
        raise AuditFailure(f"Sigstore bundle has no transparency time: {bundle}")
    return min(values)


def compact_process_note(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:500]


def ots_status(path: Path, ots: Path) -> dict[str, object]:
    receipt = path.with_suffix(path.suffix + ".ots")
    if not receipt.is_file():
        raise AuditFailure(f"OTS receipt missing: {receipt}")
    info = subprocess.run(
        [str(ots), "info", str(receipt)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if info.returncode != 0:
        raise AuditFailure(
            f"OTS receipt cannot be parsed: {(info.stderr or info.stdout)[-300:]}"
        )
    information = info.stdout + "\n" + info.stderr
    on_disk_pending = "PendingAttestation" in information
    on_disk_bitcoin = "BitcoinBlockHeaderAttestation" in information
    upgrade = subprocess.run(
        [str(ots), "upgrade", "-n", str(receipt)],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    upgrade_text = upgrade.stdout + "\n" + upgrade.stderr
    upgrade_available = (
        upgrade.returncode == 0 and "Timestamp complete" in upgrade_text
    )
    verification = subprocess.run(
        [str(ots), "verify", str(receipt)],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    verification_text = verification.stdout + "\n" + verification.stderr
    network_markers = (
        "temporary failure in name resolution",
        "name or service not known",
        "connection timed out",
        "network is unreachable",
        "urlerror",
        "connection refused",
    )
    node_unavailable = (
        "could not connect to bitcoin node" in verification_text.lower()
        or "cookie file unusable" in verification_text.lower()
    )
    calendar_network_unavailable = any(
        marker in upgrade_text.lower() for marker in network_markers
    )
    if verification.returncode == 0:
        status = "BITCOIN_CONFIRMED"
    elif upgrade_available and node_unavailable:
        status = "BITCOIN_ATTESTATION_AVAILABLE_NODE_UNAVAILABLE"
    elif upgrade_available or on_disk_bitcoin:
        status = "BITCOIN_ATTESTATION_AVAILABLE"
    elif calendar_network_unavailable:
        status = "NETWORK_UNAVAILABLE"
    elif on_disk_pending:
        status = "PENDING_CALENDAR"
    else:
        status = "UNVERIFIED"
    return {
        "receipt_sha256": sha256(receipt),
        "parsed": True,
        "status": status,
        "bitcoin_confirmed": status == "BITCOIN_CONFIRMED",
        "on_disk_pending_attestation": on_disk_pending,
        "on_disk_bitcoin_attestation": on_disk_bitcoin,
        "upgrade_available": upgrade_available,
        "upgrade_returncode": upgrade.returncode,
        "verify_returncode": verification.returncode,
        "upgrade_note": compact_process_note(upgrade_text),
        "verification_note": compact_process_note(verification_text),
    }


def ots_receipt_info(path: Path, ots: Path) -> dict[str, object]:
    """Validate an hourly OTS receipt locally without repeated network/node work."""
    receipt = path.with_suffix(path.suffix + ".ots")
    if not receipt.is_file():
        raise AuditFailure(f"OTS receipt missing: {receipt}")
    info = subprocess.run(
        [str(ots), "info", str(receipt)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if info.returncode != 0:
        raise AuditFailure(
            f"OTS receipt cannot be parsed: {(info.stderr or info.stdout)[-300:]}"
        )
    text = info.stdout + "\n" + info.stderr
    if "BitcoinBlockHeaderAttestation" in text:
        status = "BITCOIN_ATTESTATION_ON_DISK"
    elif "PendingAttestation" in text:
        status = "PENDING_CALENDAR"
    else:
        status = "UNVERIFIED"
    return {
        "receipt_sha256": sha256(receipt),
        "parsed": True,
        "status": status,
    }


def tsa_certificates(trusted_root: Path) -> tuple[str, str, str]:
    raw = trusted_root.read_bytes()
    payload = json.loads(raw)
    certificates = payload["timestampAuthorities"][0]["certChain"]["certificates"]
    if len(certificates) < 2:
        raise AuditFailure("TSA trust chain is incomplete")
    import ssl

    leaf = ssl.DER_cert_to_PEM_cert(base64.b64decode(certificates[0]["rawBytes"]))
    root = ssl.DER_cert_to_PEM_cert(base64.b64decode(certificates[-1]["rawBytes"]))
    return leaf, root, hashlib.sha256(raw).hexdigest()


def verify_rfc3161_leaf(
    response: bytes,
    public_leaf: bytes,
    *,
    openssl: Path,
    trusted_root: Path,
) -> str:
    leaf_pem, root_pem, _ = tsa_certificates(trusted_root)
    with tempfile.TemporaryDirectory(prefix="public-track-tsa-") as directory:
        root = Path(directory)
        response_path = root / "response.tsr"
        leaf_path = root / "tsa.pem"
        ca_path = root / "root.pem"
        response_path.write_bytes(response)
        leaf_path.write_text(leaf_pem)
        ca_path.write_text(root_pem)
        subprocess.run(
            [
                str(openssl),
                "ts",
                "-verify",
                "-digest",
                public_leaf.hex(),
                "-in",
                str(response_path),
                "-CAfile",
                str(ca_path),
                "-untrusted",
                str(leaf_path),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        text = subprocess.run(
            [str(openssl), "ts", "-reply", "-in", str(response_path), "-text"],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout
    match = re.search(r"^Time stamp:\s*(.+ GMT)\s*$", text, re.MULTILINE)
    if match is None:
        raise AuditFailure("TSA response has no signed time")
    value = " ".join(match.group(1).split())
    return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(
        tzinfo=timezone.utc
    ).isoformat()


def inclusion_root(leaf: bytes, path: list[dict[str, str]]) -> bytes:
    value = leaf
    for node in path:
        sibling = bytes.fromhex(str(node["sha256"]))
        side = node.get("side")
        if side not in {"left", "right"}:
            raise AuditFailure("invalid Merkle path side")
        value = hashlib.sha256(
            NODE + (sibling + value if side == "left" else value + sibling)
        ).digest()
    return value


def day_bounds(day: str) -> tuple[datetime, datetime]:
    start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return start, start + timedelta(days=1)


def expected_ids(day: str, starts_after_token: int) -> list[int]:
    start, end = day_bounds(day)
    first = max(int(start.timestamp()) // TOKEN_SECONDS, starts_after_token + 1)
    last = int(end.timestamp()) // TOKEN_SECONDS - 1
    return [] if last < first else list(range(first, last + 1))


def due_days(starts_after_token: int, now_epoch: float) -> list[dict[str, object]]:
    first_time = datetime.fromtimestamp(
        (starts_after_token + 1) * TOKEN_SECONDS, timezone.utc
    ).replace(hour=0, minute=0, second=0, microsecond=0)
    result = []
    day = first_time
    while True:
        deadline = int((day + timedelta(days=1)).timestamp()) + PACK_DELAY_SECONDS + PUBLICATION_GRACE_SECONDS
        if now_epoch < deadline:
            break
        result.append(
            {
                "day": day.date().isoformat(),
                "deadline_epoch": deadline,
                "deadline_utc": utc(deadline),
            }
        )
        day += timedelta(days=1)
    return result


def official_tokens_in_day(day: str, official_from_token: int) -> int:
    start, end = day_bounds(day)
    first = max(int(start.timestamp()) // TOKEN_SECONDS, official_from_token)
    last_exclusive = int(end.timestamp()) // TOKEN_SECONDS
    return max(0, last_exclusive - first)


def iter_jsonl_gzip(path: Path) -> Iterator[dict[str, object]]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                yield json.loads(line)
            except Exception as error:
                raise AuditFailure(f"invalid pack JSON at line {line_number}: {error}")


def core_contract(
    public_root: Path,
    *,
    openssl: Path,
    cosign: Path,
    ots: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    public_key = public_root / "PUBLIC_KEY.pem"
    amendments = public_root / "amendments"
    manifest_path = amendments / CANONICAL_MANIFEST
    contract_path = amendments / EVIDENCE_CONTRACT
    clarification_path = amendments / DEADLINE_CLARIFICATION
    release_path = amendments / VERIFIER_RELEASE
    previous_release_path = amendments / "PUBLIC_VERIFIER_RELEASE_V1_20260902.json"
    paths = (manifest_path, contract_path, clarification_path, release_path)
    for path in paths:
        if not path.is_file():
            raise AuditFailure(f"required public artifact missing: {path}")
    manifest = json.loads(manifest_path.read_text())
    contract = json.loads(contract_path.read_text())
    clarification = json.loads(clarification_path.read_text())
    release = json.loads(release_path.read_text())
    if not verify_content_hash(release):
        raise AuditFailure("public verifier release content hash mismatch")
    if (
        release.get("schema") != "laniakea-public-verifier-release-v2"
        or release.get("release_id") != "LANIAKEA-PUBLIC-VERIFIER-002"
        or release.get("capabilities", {}).get("witness_chain_mode")
        != "--witness-chain"
    ):
        raise AuditFailure("public verifier V2 release semantics mismatch")
    release_files = release["files"]
    if (
        not previous_release_path.is_file()
        or release.get("supersedes_release_sha256") != sha256(previous_release_path)
    ):
        raise AuditFailure("public verifier V1 -> V2 release seam mismatch")
    verify_ed25519(previous_release_path, public_key, openssl)
    cosign_key = public_root / str(release_files["cosign_public_key"]["path"])
    tsa_root = public_root / str(release_files["tsa_trusted_root"]["path"])
    for name, row in release_files.items():
        path = public_root / str(row["path"])
        if not path.is_file() or sha256(path) != row["sha256"]:
            raise AuditFailure(f"public verifier release file mismatch: {name}")
        verify_ed25519(path, public_key, openssl)
    if sha256(public_key) != manifest["identity"]["public_key_sha256"]:
        raise AuditFailure("public Ed25519 key hash mismatch")
    if sha256(cosign_key) != release_files["cosign_public_key"]["sha256"]:
        raise AuditFailure("Cosign public key hash mismatch")
    if sha256(tsa_root) != release_files["tsa_trusted_root"]["sha256"]:
        raise AuditFailure("TSA trusted root hash mismatch")
    if sha256(manifest_path) != release["canonical_track_manifest_sha256"]:
        raise AuditFailure("verifier release canonical-manifest link mismatch")
    if sha256(contract_path) != release["evidence_contract_v4_sha256"]:
        raise AuditFailure("verifier release contract link mismatch")
    if sha256(clarification_path) != release["deadline_clarification_v4_1_sha256"]:
        raise AuditFailure("verifier release clarification link mismatch")
    if contract["canonical_track_manifest_sha256"] != sha256(manifest_path):
        raise AuditFailure("evidence contract canonical-manifest link mismatch")
    if clarification["canonical_track_manifest_sha256"] != sha256(manifest_path):
        raise AuditFailure("deadline clarification canonical-manifest link mismatch")
    if clarification["clarifies_contract_sha256"] != sha256(contract_path):
        raise AuditFailure("deadline clarification contract link mismatch")
    if not verify_content_hash(manifest) or not verify_content_hash(contract):
        raise AuditFailure("canonical public content hash mismatch")
    spec_path = public_root / "SPEC.json"
    if (
        not spec_path.is_file()
        or sha256(spec_path) != manifest["identity"]["public_spec_sha256"]
        or sha256(spec_path) != genesis_spec_hash(public_root)
    ):
        raise AuditFailure("public Proof Tape specification hash mismatch")
    official_from = int(manifest["official_from_token"])
    official_epoch = official_from * TOKEN_SECONDS
    if manifest["official_from_utc"] != utc(official_epoch):
        raise AuditFailure("official token/time mismatch")
    if (
        int(release.get("effective_from_token", -1)) != official_from
        or release.get("effective_from_utc") != manifest["official_from_utc"]
        or int(
            clarification["full_pack_timing"][
                "external_publication_deadline_seconds_after_eligibility"
            ]
        )
        != PUBLICATION_GRACE_SECONDS
        or contract["rules"]["UNREVEALED_TOKEN_IS_MISS"][
            "missing_or_invalid_opening"
        ]
        != "ONE_PUBLIC_MISS_PER_TOKEN"
    ):
        raise AuditFailure("public verifier release/rule boundary mismatch")
    external_times = {}
    ots_results = {}
    for path in paths:
        verify_ed25519(path, public_key, openssl)
        external = sigstore_time(path, cosign, cosign_key)
        external_times[path.name] = external
        ots_results[path.name] = ots_status(path, ots)
        if external >= official_epoch:
            raise AuditFailure(f"core artifact was not externally anchored prospectively: {path.name}")
    genesis_path = public_root / "GENESIS.json"
    verify_ed25519(genesis_path, public_key, openssl)
    genesis_sigstore = sigstore_time(genesis_path, cosign, cosign_key)
    genesis_ots = ots_status(genesis_path, ots)
    genesis = json.loads(genesis_path.read_text())
    if sha256(genesis_path) != manifest["identity"]["proof_genesis_artifact_sha256"]:
        raise AuditFailure("genesis artifact link mismatch")
    if genesis["public_genesis_chain_sha256"] != manifest["identity"]["proof_genesis_chain_sha256"]:
        raise AuditFailure("genesis chain link mismatch")
    return (
        {
            "manifest": manifest,
            "contract": contract,
            "clarification": clarification,
            "release": release,
            "genesis": genesis,
            "public_key": public_key,
            "cosign_public_key": cosign_key,
            "tsa_trusted_root": tsa_root,
        },
        {
            "external_times": external_times,
            "ots": ots_results,
            "genesis_sigstore_time": genesis_sigstore,
            "genesis_ots": genesis_ots,
        },
    )


def genesis_spec_hash(public_root: Path) -> str:
    genesis = json.loads((public_root / "GENESIS.json").read_text())
    return str(genesis["public_spec_sha256"])


def verify_witness(
    public_root: Path,
    witness: dict[str, object],
    *,
    public_key: Path,
    cosign: Path,
    cosign_public_key: Path,
    openssl: Path,
    cache: dict[str, dict[str, object]],
) -> dict[str, object]:
    identifier = str(witness["identifier"])
    if identifier in cache:
        return cache[identifier]
    artifact = public_root / str(witness["artifact"])
    if not artifact.is_file() or sha256(artifact) != witness["artifact_sha256"]:
        raise AuditFailure(f"witness artifact hash mismatch: {identifier}")
    verify_ed25519(artifact, public_key, openssl)
    external_time = sigstore_time(artifact, cosign, cosign_public_key)
    payload = json.loads(artifact.read_text())
    if (
        payload.get("identifier") != identifier
        or payload.get("merkle_root_sha256") != witness["merkle_root_sha256"]
        or int(payload.get("record_count", -1)) != int(witness["records"])
        or payload.get("first_token_id") != witness.get("first_token")
        or payload.get("last_token_id") != witness.get("last_token")
    ):
        raise AuditFailure(f"witness metadata mismatch: {identifier}")
    slot = datetime.strptime(identifier, "%Y%m%d_%H%M").replace(tzinfo=timezone.utc)
    previous_identifier = (slot - timedelta(minutes=5)).strftime("%Y%m%d_%H%M")
    previous_path = public_root / "witnesses" / f"{previous_identifier}.json"
    expected_previous = (
        sha256(previous_path)
        if previous_path.is_file()
        else sha256(public_root / "GENESIS.json")
    )
    if payload.get("previous_artifact_sha256") != expected_previous:
        raise AuditFailure(f"witness artifact-chain seam mismatch: {identifier}")
    result = {"payload": payload, "external_time": external_time, "artifact": artifact}
    cache[identifier] = result
    return result


def verify_hour(
    public_root: Path,
    hour_identifier: str,
    *,
    public_key: Path,
    cosign: Path,
    cosign_public_key: Path,
    openssl: Path,
    ots: Path,
    cache: dict[str, dict[str, object]],
) -> dict[str, object]:
    if hour_identifier in cache:
        return cache[hour_identifier]
    artifact = public_root / "hours" / f"{hour_identifier}.json"
    if not artifact.is_file():
        raise AuditFailure(f"hour artifact missing: {hour_identifier}")
    verify_ed25519(artifact, public_key, openssl)
    external_time = sigstore_time(artifact, cosign, cosign_public_key)
    receipt = ots_status(artifact, ots)
    payload = json.loads(artifact.read_text())
    if payload.get("identifier") != hour_identifier:
        raise AuditFailure(f"hour artifact identifier mismatch: {hour_identifier}")
    hour = datetime.strptime(hour_identifier, "%Y%m%d_%H").replace(
        tzinfo=timezone.utc
    )
    previous_identifier = (hour - timedelta(hours=1)).strftime("%Y%m%d_%H")
    previous_path = public_root / "hours" / f"{previous_identifier}.json"
    expected_previous = (
        sha256(previous_path)
        if previous_path.is_file()
        else sha256(public_root / "GENESIS.json")
    )
    if payload.get("previous_artifact_sha256") != expected_previous:
        raise AuditFailure(f"hour artifact-chain seam mismatch: {hour_identifier}")
    result = {
        "external_time": external_time,
        "ots": receipt,
        "sha256": sha256(artifact),
    }
    cache[hour_identifier] = result
    return result


def valid_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_chain_external_artifact(
    row: dict[str, object],
    *,
    public_key: Path,
    cosign: Path,
    cosign_public_key: Path,
    openssl: Path,
    ots: Path,
) -> dict[str, object]:
    path = Path(row["path"])
    verify_ed25519(path, public_key, openssl)
    external = sigstore_time(path, cosign, cosign_public_key)
    created = float(row["created_epoch"])
    interval_end = float(row["interval_end_epoch"])
    if external + 1 < created or external + 1 < interval_end:
        raise AuditFailure(f"external time precedes artifact creation/interval: {path.name}")
    result: dict[str, object] = {
        "identifier": row["identifier"],
        "sha256": row["sha256"],
        "sigstore_time": external,
    }
    if row["kind"] == "hour":
        result["ots"] = ots_receipt_info(path, ots)
    return result


def verify_public_artifact_chain(
    public_root: Path,
    *,
    folder: str,
    kind: str,
    seconds: int,
    now_epoch: float,
    settle_seconds: int,
    workers: int,
    public_key: Path,
    cosign: Path,
    cosign_public_key: Path,
    openssl: Path,
    ots: Path,
) -> dict[str, object]:
    failures: list[str] = []
    base = public_root / folder
    paths = sorted(
        path
        for path in base.glob("*.json")
        if not path.name.endswith(".sigstore.json")
    )
    cutoff = now_epoch - settle_seconds
    settled: list[dict[str, object]] = []
    pending = []
    expected_schema = (
        "proof-tape-public-five-minute-witness-v2"
        if kind == "witness"
        else "proof-tape-public-hour-v2"
    )
    identifier_format = "%Y%m%d_%H%M" if kind == "witness" else "%Y%m%d_%H"
    public_spec_hash = sha256(public_root / "SPEC.json")
    for path in paths:
        try:
            payload = json.loads(path.read_text())
            start = epoch(str(payload["interval_start_utc"]))
            end = epoch(str(payload["interval_end_utc"]))
            identifier = str(payload["identifier"])
            row = {
                "path": path,
                "payload": payload,
                "identifier": identifier,
                "start_epoch": start,
                "interval_end_epoch": end,
                "created_epoch": epoch(str(payload["created_utc"])),
                "sha256": sha256(path),
                "kind": kind,
            }
            if end <= cutoff:
                settled.append(row)
            else:
                pending.append(identifier)
        except Exception as error:
            failures.append(f"parse {path.name}: {type(error).__name__}: {error}")
    settled.sort(key=lambda row: (float(row["start_epoch"]), str(row["identifier"])))
    previous_hash = sha256(public_root / "GENESIS.json")
    previous_end = None
    for row in settled:
        payload = row["payload"]
        identifier = str(row["identifier"])
        start = float(row["start_epoch"])
        end = float(row["interval_end_epoch"])
        count = int(payload.get("record_count", -1))
        expected_identifier = datetime.fromtimestamp(start, timezone.utc).strftime(
            identifier_format
        )
        checks = {
            "schema": payload.get("schema") == expected_schema,
            "filename": Path(row["path"]).stem == identifier,
            "identifier": identifier == expected_identifier,
            "alignment": int(start) % seconds == 0 and end - start == seconds,
            "sequence": previous_end is None or start == previous_end,
            "previous_hash": payload.get("previous_artifact_sha256") == previous_hash,
            "creation_after_interval": float(row["created_epoch"]) + 1 >= end,
            "record_count": count >= 0,
            "record_bounds": (
                payload.get("first_token_id") is None
                and payload.get("last_token_id") is None
                if count == 0
                else isinstance(payload.get("first_token_id"), int)
                and isinstance(payload.get("last_token_id"), int)
                and int(payload["first_token_id"]) <= int(payload["last_token_id"])
            ),
            "merkle_root": valid_sha256_hex(payload.get("merkle_root_sha256")),
            "chain_head": valid_sha256_hex(payload.get("public_chain_head_sha256")),
            "public_spec": payload.get("public_spec_sha256") == public_spec_hash,
            "claim_hidden": payload.get("claim_content_before_reveal") == "NONE",
        }
        failures.extend(
            f"{identifier}:{name}" for name, passed in checks.items() if not passed
        )
        previous_hash = str(row["sha256"])
        previous_end = end
    expected_last_end = int(cutoff // seconds * seconds)
    if not settled:
        failures.append("no settled artifacts")
    elif int(float(settled[-1]["interval_end_epoch"])) != expected_last_end:
        failures.append(
            f"settled prefix ends at {int(float(settled[-1]['interval_end_epoch']))}, "
            f"expected {expected_last_end}"
        )

    external_results = []
    if settled:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            futures = {
                executor.submit(
                    verify_chain_external_artifact,
                    row,
                    public_key=public_key,
                    cosign=cosign,
                    cosign_public_key=cosign_public_key,
                    openssl=openssl,
                    ots=ots,
                ): str(row["identifier"])
                for row in settled
            }
            for future in as_completed(futures):
                identifier = futures[future]
                try:
                    external_results.append(future.result())
                except Exception as error:
                    failures.append(
                        f"{identifier}:external:{type(error).__name__}:{str(error)[:300]}"
                    )
    external_results.sort(key=lambda row: str(row["identifier"]))
    ots_counts = Counter(
        str(row["ots"]["status"])
        for row in external_results
        if "ots" in row
    )
    return {
        "status": "PASS" if not failures else "HOLD",
        "kind": kind,
        "interval_seconds": seconds,
        "settle_seconds": settle_seconds,
        "settled_artifacts": len(settled),
        "externally_verified_artifacts": len(external_results),
        "first_identifier": settled[0]["identifier"] if settled else None,
        "last_identifier": settled[-1]["identifier"] if settled else None,
        "expected_last_interval_end_utc": utc(expected_last_end),
        "pending_settlement": pending,
        "ots_status_counts": dict(sorted(ots_counts.items())),
        "merkle_content_status": "COMMITMENT_ONLY_UNTIL_FULL_PACK_OPENING",
        "failures": failures[:200],
    }


def verify_witness_chains(
    public_root: Path,
    *,
    now_epoch: float,
    settle_seconds: int,
    workers: int,
    public_key: Path,
    cosign: Path,
    cosign_public_key: Path,
    openssl: Path,
    ots: Path,
) -> dict[str, object]:
    witnesses = verify_public_artifact_chain(
        public_root,
        folder="witnesses",
        kind="witness",
        seconds=300,
        now_epoch=now_epoch,
        settle_seconds=settle_seconds,
        workers=workers,
        public_key=public_key,
        cosign=cosign,
        cosign_public_key=cosign_public_key,
        openssl=openssl,
        ots=ots,
    )
    hours = verify_public_artifact_chain(
        public_root,
        folder="hours",
        kind="hour",
        seconds=3600,
        now_epoch=now_epoch,
        settle_seconds=settle_seconds,
        workers=workers,
        public_key=public_key,
        cosign=cosign,
        cosign_public_key=cosign_public_key,
        openssl=openssl,
        ots=ots,
    )
    return {
        "status": (
            "PASS"
            if witnesses["status"] == "PASS" and hours["status"] == "PASS"
            else "HOLD"
        ),
        "witnesses": witnesses,
        "hours": hours,
    }


def verify_pack(
    manifest_path: Path,
    *,
    public_root: Path,
    core: dict[str, object],
    openssl: Path,
    cosign: Path,
    ots: Path,
    expected_day: str,
    deadline_epoch: int,
    previous_chain: str,
    witness_cache: dict[str, dict[str, object]],
    hour_cache: dict[str, dict[str, object]],
) -> dict[str, object]:
    public_key = core["public_key"]
    cosign_key = core["cosign_public_key"]
    trusted_root = core["tsa_trusted_root"]
    verify_ed25519(manifest_path, public_key, openssl)
    manifest_external = sigstore_time(manifest_path, cosign, cosign_key)
    manifest_ots = ots_status(manifest_path, ots)
    manifest = json.loads(manifest_path.read_text())
    if manifest_external > deadline_epoch:
        return {
            "status": "LATE_PACK",
            "manifest_external_time": manifest_external,
            "manifest": manifest,
            "full_day_penalty": True,
            "ots": manifest_ots,
        }
    if manifest.get("schema") != "proof-tape-full-token-pack-v2":
        raise AuditFailure(f"pack schema mismatch: {expected_day}")
    if manifest.get("day_utc") != expected_day or manifest.get("forced_before_eligibility"):
        raise AuditFailure(f"pack day/eligibility mismatch: {expected_day}")
    if int(manifest.get("delay_seconds", -1)) != PACK_DELAY_SECONDS:
        raise AuditFailure(f"pack delay mismatch: {expected_day}")
    contract_files = {
        "canonical_track_manifest": CANONICAL_MANIFEST,
        "evidence_contract_v4": EVIDENCE_CONTRACT,
        "deadline_clarification_v4_1": DEADLINE_CLARIFICATION,
    }
    declared = manifest.get("evidence_contract", {}).get("artifacts_sha256", {})
    if set(declared) != set(contract_files):
        raise AuditFailure(f"pack evidence contract set mismatch: {expected_day}")
    for name, filename in contract_files.items():
        if declared[name] != sha256(public_root / "amendments" / filename):
            raise AuditFailure(f"pack evidence contract hash mismatch: {name}")
    pack = public_root / str(manifest["pack"]["path"])
    if (
        not pack.is_file()
        or pack.stat().st_size != int(manifest["pack"]["bytes"])
        or sha256(pack) != manifest["pack"]["sha256"]
    ):
        raise AuditFailure(f"pack file hash/size mismatch: {expected_day}")
    rows = list(iter_jsonl_gzip(pack))
    ids = [int(row["token_id"]) for row in rows]
    expected = expected_ids(expected_day, int(core["genesis"]["starts_after_token"]))
    if ids != expected:
        raise AuditFailure(f"pack does not cover complete expected grid: {expected_day}")
    if (
        len(rows) != int(manifest["token_count"])
        or len(rows) != int(manifest["expected_token_count"])
        or int(manifest["opened_token_count"])
        + int(manifest["unrevealed_token_count"])
        != len(rows)
    ):
        raise AuditFailure(f"pack population mismatch: {expected_day}")
    if manifest["previous_public_chain_sha256"] != previous_chain:
        raise AuditFailure(f"cross-pack public-chain seam mismatch: {expected_day}")

    chain = bytes.fromhex(previous_chain)
    chain_recomputable = True
    claims = Counter()
    unrevealed = []
    signal_rows = []
    slot_rows: dict[str, list[dict[str, object]]] = defaultdict(list)
    trusted_time_by_token: dict[int, float] = {}
    witness_manifest = {
        str(row["identifier"]): row for row in manifest["five_minute_witnesses"]
    }
    openings = {
        str(row["identifier"]): row
        for row in manifest["signal_count_commitment_openings"]
    }
    official_from = int(core["manifest"]["official_from_token"])
    private_tsa_from = int(
        core["contract"]["rules"]["TSA_BEFORE_OUTCOME"][
            "private_rfc3161_required_from_token"
        ]
    )
    claim_keys = {
        "schema",
        "epoch",
        "token_id",
        "source_time_utc",
        "issued_time_utc",
        "claim_kind",
        "direction_if_signal",
    }
    invalid_timing_tokens = []
    for row in rows:
        token = int(row["token_id"])
        if int(row["source_ts"]) != token * TOKEN_SECONDS:
            raise AuditFailure(f"token/source-time mismatch: {token}")
        if row.get("opening_status") == "UNREVEALED":
            if row.get("public_score") != "MISS":
                raise AuditFailure(f"unrevealed token lacks miss penalty: {token}")
            unrevealed.append(token)
            claims["UNREVEALED"] += 1
            chain_recomputable = False
            continue
        if row.get("opening_status") != "OPENED":
            raise AuditFailure(f"unknown opening status: {token}")
        claim = row["public_claim"]
        if (
            set(claim) != claim_keys
            or claim.get("schema") != "proof-tape-public-claim-v2"
            or int(claim.get("token_id", -1)) != token
            or claim.get("source_time_utc") != utc(token * TOKEN_SECONDS)
            or claim.get("issued_time_utc") != row.get("issued_utc")
            or claim.get("claim_kind") not in {"NO_SIGNAL", "SIGNAL"}
            or (
                claim.get("direction_if_signal") is not None
                if claim.get("claim_kind") == "NO_SIGNAL"
                else claim.get("direction_if_signal") not in {"LONG", "SHORT"}
            )
        ):
            raise AuditFailure(f"public claim semantics mismatch: {token}")
        salt = bytes.fromhex(str(row["public_salt_hex"]))
        leaf = hashlib.sha256(PUB_LEAF + salt + canonical(claim)).digest()
        if leaf.hex() != row["public_leaf_sha256"]:
            raise AuditFailure(f"public leaf mismatch: {token}")
        if chain_recomputable:
            chain = hashlib.sha256(
                PUB_CHAIN + chain + struct.pack(">Q", token) + leaf
            ).digest()
            if chain.hex() != row["public_chain_sha256"]:
                raise AuditFailure(f"public chain mismatch: {token}")
        witness_ref = row["witness"]
        identifier = str(witness_ref["identifier"])
        witness_row = witness_manifest.get(identifier)
        if witness_row is None:
            raise AuditFailure(f"pack witness missing: {identifier}")
        witness = verify_witness(
            public_root,
            witness_row,
            public_key=public_key,
            cosign=cosign,
            cosign_public_key=cosign_key,
            openssl=openssl,
            cache=witness_cache,
        )
        if inclusion_root(leaf, witness_ref["merkle_path"]).hex() != witness_ref[
            "merkle_root_sha256"
        ]:
            raise AuditFailure(f"Merkle inclusion mismatch: {token}")
        if witness_ref["merkle_root_sha256"] != witness_row["merkle_root_sha256"]:
            raise AuditFailure(f"witness root reference mismatch: {token}")
        slot_rows[identifier].append(row)
        interval_start = datetime.fromisoformat(
            str(witness["payload"]["interval_start_utc"])
        )
        hour_identifier = interval_start.astimezone(timezone.utc).strftime("%Y%m%d_%H")
        verify_hour(
            public_root,
            hour_identifier,
            public_key=public_key,
            cosign=cosign,
            cosign_public_key=cosign_key,
            openssl=openssl,
            ots=ots,
            cache=hour_cache,
        )
        if claim["claim_kind"] == "NO_SIGNAL":
            claims["NO_SIGNAL"] += 1
        else:
            claims[f"SIGNAL_{claim['direction_if_signal']}"] += 1
            signal_rows.append(row)
            external_time = None
            receipt = row.get("private_rfc3161")
            if token >= private_tsa_from:
                if receipt is not None:
                    try:
                        response = base64.b64decode(receipt["response_der_base64"])
                        if hashlib.sha256(response).hexdigest() != receipt["response_sha256"]:
                            raise AuditFailure("RFC3161 response hash mismatch")
                        if sha256(trusted_root) != receipt["trusted_root_sha256"]:
                            raise AuditFailure("RFC3161 trusted-root hash mismatch")
                        signed_time = verify_rfc3161_leaf(
                            response,
                            leaf,
                            openssl=openssl,
                            trusted_root=trusted_root,
                        )
                        if signed_time != receipt["tsa_time_utc"]:
                            raise AuditFailure("RFC3161 signed-time mismatch")
                        external_time = epoch(signed_time)
                    except Exception:
                        external_time = None
            else:
                external_time = float(witness["external_time"])
            if external_time is not None:
                trusted_time_by_token[token] = external_time
            else:
                invalid_timing_tokens.append(token)

    if chain_recomputable and chain.hex() != manifest["final_public_chain_sha256"]:
        raise AuditFailure(f"pack final chain mismatch: {expected_day}")
    declared_unrevealed = [int(value) for value in manifest["unrevealed_token_ids"]]
    if (
        unrevealed != declared_unrevealed
        or len(unrevealed) != int(manifest["unrevealed_token_count"])
        or len(unrevealed) != int(manifest["unrevealed_token_misses"])
    ):
        raise AuditFailure(f"unrevealed-token declaration mismatch: {expected_day}")
    normalized_claims = {
        key: int(claims.get(key, 0))
        for key in ("NO_SIGNAL", "SIGNAL_LONG", "SIGNAL_SHORT", "UNREVEALED")
    }
    if normalized_claims != {
        key: int(value) for key, value in manifest["claim_counts"].items()
    }:
        raise AuditFailure(f"claim counts mismatch: {expected_day}")
    for identifier, relevant in slot_rows.items():
        witness = witness_manifest[identifier]
        if len(relevant) != int(witness["records"]):
            continue
        opening = openings.get(identifier)
        if opening is None:
            if any(int(row["token_id"]) >= official_from for row in relevant):
                raise AuditFailure(f"official signal-count opening missing: {identifier}")
            continue
        actual_signals = sum(
            row["public_claim"]["claim_kind"] == "SIGNAL" for row in relevant
        )
        commitment = hashlib.sha256(
            SIGNAL_COUNT
            + bytes.fromhex(str(opening["salt_hex"]))
            + identifier.encode()
            + struct.pack(">Q", int(opening["signal_count"]))
        ).hexdigest()
        witness_payload = witness_cache[identifier]["payload"]
        if (
            commitment != opening["commitment_sha256"]
            or commitment != witness_payload.get("signal_count_commitment_sha256")
            or int(opening["signal_count"]) != actual_signals
        ):
            raise AuditFailure(f"signal-count commitment mismatch: {identifier}")
    return {
        "status": "ON_TIME_COMPLETE" if not unrevealed else "ON_TIME_INCOMPLETE",
        "manifest": manifest,
        "manifest_external_time": manifest_external,
        "ots": manifest_ots,
        "rows": rows,
        "signal_rows": signal_rows,
        "trusted_time_by_token": trusted_time_by_token,
        "invalid_timing_tokens": invalid_timing_tokens,
        "unrevealed_tokens": unrevealed,
        "claim_counts": normalized_claims,
        "final_chain": chain.hex() if chain_recomputable else None,
        "full_day_penalty": False,
    }


def _csv_events(text: io.TextIOBase, source: str) -> Iterator[tuple[int, int, float]]:
    reader = csv.reader(text)
    first = True
    for line_number, row in enumerate(reader, 1):
        if not row:
            continue
        if first and not row[0].strip().lstrip("-").isdigit():
            first = False
            continue
        first = False
        try:
            yield int(row[0]), int(row[5]), float(row[1])
        except Exception as error:
            raise AuditFailure(f"invalid Binance CSV row {source}:{line_number}: {error}")


def _ndjson_events(text: io.TextIOBase, source: str) -> Iterator[tuple[int, int, float]]:
    for line_number, line in enumerate(text, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            yield int(row["a"]), int(row["T"]), float(row["p"])
        except Exception as error:
            raise AuditFailure(f"invalid Binance NDJSON row {source}:{line_number}: {error}")


def events_from_file(path: Path) -> Iterator[tuple[int, int, float]]:
    lower = path.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            members = sorted(
                name for name in archive.namelist() if not name.endswith("/")
            )
            if not members:
                raise AuditFailure(f"empty Binance archive: {path}")
            for name in members:
                with archive.open(name) as raw:
                    with io.TextIOWrapper(raw, encoding="utf-8") as text:
                        yield from _csv_events(text, f"{path}:{name}")
        return
    if lower.endswith((".ndjson.gz", ".jsonl.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as text:
            yield from _ndjson_events(text, str(path))
        return
    if lower.endswith(".csv.gz"):
        with gzip.open(path, "rt", encoding="utf-8") as text:
            yield from _csv_events(text, str(path))
        return
    if lower.endswith((".ndjson", ".jsonl")):
        with path.open(encoding="utf-8") as text:
            yield from _ndjson_events(text, str(path))
        return
    if lower.endswith(".csv"):
        with path.open(encoding="utf-8") as text:
            yield from _csv_events(text, str(path))
        return
    raise AuditFailure(f"unsupported Binance tape file: {path}")


def tape_files(path: Path) -> list[Path]:
    supported = (".zip", ".csv", ".csv.gz", ".ndjson", ".ndjson.gz", ".jsonl", ".jsonl.gz")
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise AuditFailure(f"Binance tape path missing: {path}")
    files = sorted(
        file
        for file in path.rglob("*")
        if file.is_file() and file.name.lower().endswith(supported)
    )
    if not files:
        raise AuditFailure(f"no supported Binance tape files under {path}")
    return files


def load_binance_closes(path: Path) -> dict[str, object]:
    closes: dict[int, tuple[int, int, float]] = {}
    previous_id = None
    event_count = 0
    minimum_ms = None
    maximum_ms = None
    for file in tape_files(path):
        file_first = None
        file_last = None
        last_in_file = None
        for event_id, event_ms, price in events_from_file(file):
            if price <= 0 or event_ms < 0:
                raise AuditFailure(f"non-positive Binance event payload: {file}")
            if last_in_file is not None and event_id <= last_in_file:
                raise AuditFailure(f"Binance archive is not strictly ID ordered: {file}")
            if last_in_file is not None and event_id != last_in_file + 1:
                raise AuditFailure(f"Binance archive has an aggTrade ID gap: {file}")
            last_in_file = event_id
            file_first = event_id if file_first is None else file_first
            file_last = event_id
            event_count += 1
            minimum_ms = event_ms if minimum_ms is None else min(minimum_ms, event_ms)
            maximum_ms = event_ms if maximum_ms is None else max(maximum_ms, event_ms)
            token = event_ms // (TOKEN_SECONDS * 1000)
            candidate = (event_ms, event_id, price)
            if token not in closes or candidate[:2] > closes[token][:2]:
                closes[token] = candidate
        if file_first is None:
            continue
        if previous_id is not None and file_first <= previous_id:
            raise AuditFailure(
                "Binance input archives overlap; provide one clean, non-overlapping public tape"
            )
        if previous_id is not None and file_first != previous_id + 1:
            raise AuditFailure("Binance input archives have an aggTrade ID gap")
        previous_id = file_last
    if not closes:
        raise AuditFailure("Binance tape contains no events")
    tokens = sorted(closes)
    return {
        "updates": {token: closes[token][2] for token in tokens},
        "tokens": tokens,
        "event_count": event_count,
        "minimum_event_ms": minimum_ms,
        "maximum_event_ms": maximum_ms,
        "file_count": len(tape_files(path)),
    }


def independent_resolution(
    signal: dict[str, object],
    tape: dict[str, object],
) -> dict[str, object]:
    token = int(signal["token_id"])
    issued = epoch(str(signal["issued_utc"]))
    expiry_token = int((issued + MAX_RESOLUTION_SECONDS) // TOKEN_SECONDS)
    tokens: list[int] = tape["tokens"]
    updates: dict[int, float] = tape["updates"]
    entry_index = bisect.bisect_right(tokens, token) - 1
    if entry_index < 0:
        raise AuditFailure(f"Binance tape lacks entry price before token {token}")
    entry = float(updates[tokens[entry_index]])
    upper = entry * 1.01
    lower = entry * 0.99
    index = bisect.bisect_right(tokens, token)
    while index < len(tokens) and tokens[index] <= expiry_token:
        future_token = tokens[index]
        close = float(updates[future_token])
        if close >= upper:
            return {
                "status": "RESOLVED",
                "barrier_direction": 1,
                "resolution_token": future_token,
                "resolution_ts": future_token * TOKEN_SECONDS,
                "entry": entry,
            }
        if close <= lower:
            return {
                "status": "RESOLVED",
                "barrier_direction": 0,
                "resolution_token": future_token,
                "resolution_ts": future_token * TOKEN_SECONDS,
                "entry": entry,
            }
        index += 1
    required_end_ms = int((issued + MAX_RESOLUTION_SECONDS) * 1000)
    if int(tape["maximum_event_ms"]) < required_end_ms:
        return {
            "status": "INSUFFICIENT_TAPE",
            "required_end_ms": required_end_ms,
            "available_end_ms": int(tape["maximum_event_ms"]),
            "entry": entry,
        }
    return {
        "status": "EXPIRED",
        "barrier_direction": None,
        "resolution_token": None,
        "resolution_ts": None,
        "entry": entry,
    }


def score_rows(
    pack_results: list[dict[str, object]],
    *,
    official_from: int,
    tape: dict[str, object] | None,
) -> dict[str, object]:
    score = {"hits": 0, "misses": 0}
    timing_misses = 0
    unresolved_misses = 0
    unrevealed_misses = 0
    rejudge_mismatches = []
    insufficient_tape = []
    declared_nonindependent = {"hits": 0, "misses": 0}
    for pack in pack_results:
        manifest = pack.get("manifest", {})
        day = str(manifest.get("day_utc", ""))
        if pack.get("full_day_penalty"):
            misses = official_tokens_in_day(day, official_from)
            score["misses"] += misses
            unrevealed_misses += misses
            continue
        for token in pack["unrevealed_tokens"]:
            if int(token) >= official_from:
                score["misses"] += 1
                unrevealed_misses += 1
        for row in pack["signal_rows"]:
            token = int(row["token_id"])
            if token < official_from:
                continue
            claim = row["public_claim"]
            predicted = 1 if claim["direction_if_signal"] == "LONG" else 0
            declared = row.get("resolution") or {}
            declared_outcome = declared.get("barrier_direction")
            declared_ts = declared.get("resolution_ts")
            external = pack["trusted_time_by_token"].get(token)
            declared_timing = (
                external is not None
                and declared_ts is not None
                and float(external) < float(declared_ts)
                and float(declared_ts)
                <= epoch(str(row["issued_utc"])) + MAX_RESOLUTION_SECONDS
            )
            if declared_outcome in {0, 1} and declared_timing:
                declared_nonindependent[
                    "hits" if predicted == int(declared_outcome) else "misses"
                ] += 1
            else:
                declared_nonindependent["misses"] += 1
            if tape is None:
                continue
            independent = independent_resolution(row, tape)
            if independent["status"] == "INSUFFICIENT_TAPE":
                insufficient_tape.append(token)
                continue
            independent_outcome = independent.get("barrier_direction")
            independent_ts = independent.get("resolution_ts")
            declared_tuple = (
                declared_outcome,
                declared.get("resolution_token"),
                declared_ts,
            )
            independent_tuple = (
                independent_outcome,
                independent.get("resolution_token"),
                independent_ts,
            )
            if declared_tuple != independent_tuple:
                rejudge_mismatches.append(
                    {
                        "token_id": token,
                        "declared": declared_tuple,
                        "independent": independent_tuple,
                    }
                )
            if independent_outcome not in {0, 1}:
                score["misses"] += 1
                unresolved_misses += 1
                continue
            if external is None or not float(external) < float(independent_ts):
                score["misses"] += 1
                timing_misses += 1
                continue
            score["hits" if predicted == int(independent_outcome) else "misses"] += 1
    score["denominator"] = score["hits"] + score["misses"]
    score["hit_rate"] = (
        score["hits"] / score["denominator"] if score["denominator"] else None
    )
    declared_nonindependent["denominator"] = (
        declared_nonindependent["hits"] + declared_nonindependent["misses"]
    )
    declared_nonindependent["hit_rate"] = (
        declared_nonindependent["hits"] / declared_nonindependent["denominator"]
        if declared_nonindependent["denominator"]
        else None
    )
    return {
        "score": score,
        "declared_score_nonindependent": declared_nonindependent,
        "timing_misses": timing_misses,
        "unresolved_or_expired_misses": unresolved_misses,
        "unrevealed_or_missing_pack_misses": unrevealed_misses,
        "rejudge_mismatches": rejudge_mismatches,
        "insufficient_tape_tokens": insufficient_tape,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--binance-tape", type=Path)
    parser.add_argument("--openssl", type=Path, default=Path(shutil.which("openssl") or "openssl"))
    parser.add_argument("--cosign", type=Path, default=Path(shutil.which("cosign") or "cosign"))
    parser.add_argument("--ots", type=Path, default=Path(shutil.which("ots") or "ots"))
    parser.add_argument("--now-epoch", type=float, default=time.time())
    parser.add_argument(
        "--witness-chain",
        action="store_true",
        help="verify the settled five-minute and hourly artifact chains even before packs open",
    )
    parser.add_argument("--witness-settle-seconds", type=int, default=120)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    if args.witness_settle_seconds < 0 or args.workers <= 0:
        parser.error("witness settle seconds must be non-negative and workers positive")
    started = time.time()
    failures = []
    core = None
    core_evidence = None
    pack_results = []
    missing_or_invalid_days = []
    penalty_misses = 0
    try:
        core, core_evidence = core_contract(
            args.public_root,
            openssl=args.openssl,
            cosign=args.cosign,
            ots=args.ots,
        )
        genesis = core["genesis"]
        official_from = int(core["manifest"]["official_from_token"])
        witness_chain = {"status": "NOT_REQUESTED"}
        if args.witness_chain:
            witness_chain = verify_witness_chains(
                args.public_root,
                now_epoch=args.now_epoch,
                settle_seconds=args.witness_settle_seconds,
                workers=args.workers,
                public_key=core["public_key"],
                cosign=args.cosign,
                cosign_public_key=core["cosign_public_key"],
                openssl=args.openssl,
                ots=args.ots,
            )
            if witness_chain["status"] != "PASS":
                failures.append("WITNESS_CHAIN_HOLD")
        days = due_days(int(genesis["starts_after_token"]), args.now_epoch)
        previous_chain = str(genesis["public_genesis_chain_sha256"])
        witness_cache: dict[str, dict[str, object]] = {}
        hour_cache: dict[str, dict[str, object]] = {}
        for due in days:
            day = str(due["day"])
            path = args.public_root / "manifests" / f"FULL_TOKEN_PACK_{day}.json"
            if not path.is_file():
                missing_or_invalid_days.append(
                    {"day": day, "status": "MISSING_PACK", "deadline_utc": due["deadline_utc"]}
                )
                penalty_misses += official_tokens_in_day(day, official_from)
                continue
            try:
                result = verify_pack(
                    path,
                    public_root=args.public_root,
                    core=core,
                    openssl=args.openssl,
                    cosign=args.cosign,
                    ots=args.ots,
                    expected_day=day,
                    deadline_epoch=int(due["deadline_epoch"]),
                    previous_chain=previous_chain,
                    witness_cache=witness_cache,
                    hour_cache=hour_cache,
                )
                pack_results.append(result)
                if result["full_day_penalty"]:
                    missing_or_invalid_days.append(
                        {"day": day, "status": result["status"], "deadline_utc": due["deadline_utc"]}
                    )
                elif result["status"] == "ON_TIME_INCOMPLETE":
                    missing_or_invalid_days.append(
                        {"day": day, "status": result["status"], "deadline_utc": due["deadline_utc"]}
                    )
                if result.get("final_chain") is not None:
                    previous_chain = str(result["final_chain"])
                else:
                    previous_chain = "UNRECOMPUTABLE"
            except Exception as error:
                missing_or_invalid_days.append(
                    {
                        "day": day,
                        "status": "INVALID_PACK",
                        "deadline_utc": due["deadline_utc"],
                        "error": f"{type(error).__name__}: {str(error)[:500]}",
                    }
                )
                penalty_misses += official_tokens_in_day(day, official_from)
        tape = load_binance_closes(args.binance_tape) if args.binance_tape else None
        scored = score_rows(pack_results, official_from=official_from, tape=tape)
        if penalty_misses:
            scored["score"]["misses"] += penalty_misses
            scored["score"]["denominator"] += penalty_misses
            scored["score"]["hit_rate"] = (
                scored["score"]["hits"] / scored["score"]["denominator"]
                if scored["score"]["denominator"]
                else None
            )
            scored["unrevealed_or_missing_pack_misses"] += penalty_misses
        crypto_status = (
            "PASS" if not missing_or_invalid_days and not failures else "HOLD"
        )
        official_due = any(
            official_tokens_in_day(str(row["day"]), official_from) for row in days
        )
        if tape is None:
            market_status = "PENDING_PUBLIC_BINANCE_TAPE" if official_due else "PENDING_FIRST_OFFICIAL_PACK"
            score_status = (
                "PENDING_INDEPENDENT_MARKET_REJUDGE"
                if official_due
                else "PENDING_FIRST_OFFICIAL_PACK"
            )
        elif scored["insufficient_tape_tokens"]:
            market_status = "HOLD_INSUFFICIENT_TAPE"
            score_status = "HOLD"
        elif scored["rejudge_mismatches"]:
            market_status = "HOLD_REJUDGE_MISMATCH"
            score_status = "HOLD"
        else:
            market_status = "PASS" if official_due else "PENDING_FIRST_OFFICIAL_PACK"
            score_status = "FINAL" if official_due else "PENDING"
        statuses = {
            "CRYPTOGRAPHIC_INTEGRITY": crypto_status,
            "INDEPENDENT_MARKET_REJUDGE": market_status,
            "PUBLIC_SCORE": {
                "status": score_status,
                **scored["score"],
            },
        }
        verdict = (
            "PASS"
            if crypto_status == "PASS"
            and not market_status.startswith("HOLD")
            and score_status != "HOLD"
            else "HOLD"
        )
        result = {
            "schema": "laniakea-public-track-verification-v2",
            "verdict": verdict,
            "track_id": core["manifest"]["track_id"],
            "as_of_utc": utc(args.now_epoch),
            "statuses": statuses,
            "core_evidence": core_evidence,
            "witness_chain": witness_chain,
            "due_days": days,
            "verified_pack_days": [
                row["manifest"]["day_utc"] for row in pack_results
            ],
            "missing_or_invalid_days": missing_or_invalid_days,
            "declared_score_nonindependent": scored["declared_score_nonindependent"],
            "timing_misses": scored["timing_misses"],
            "unresolved_or_expired_misses": scored["unresolved_or_expired_misses"],
            "unrevealed_or_missing_pack_misses": scored[
                "unrevealed_or_missing_pack_misses"
            ],
            "rejudge_mismatch_count": len(scored["rejudge_mismatches"]),
            "rejudge_mismatches": scored["rejudge_mismatches"][:100],
            "insufficient_tape_tokens": scored["insufficient_tape_tokens"][:100],
            "binance_tape": (
                None
                if tape is None
                else {
                    key: value
                    for key, value in tape.items()
                    if key not in {"updates", "tokens"}
                }
            ),
            "dependencies": {
                "private_databases": False,
                "private_keys": False,
                "model_or_recipe": False,
                "python_nonstdlib_packages": False,
                "external_binaries": [str(args.openssl), str(args.cosign), str(args.ots)],
            },
            "duration_seconds": round(time.time() - started, 3),
            "failures": failures,
        }
    except Exception as error:
        result = {
            "schema": "laniakea-public-track-verification-v2",
            "verdict": "HOLD",
            "as_of_utc": utc(args.now_epoch),
            "statuses": {
                "CRYPTOGRAPHIC_INTEGRITY": "HOLD",
                "INDEPENDENT_MARKET_REJUDGE": "NOT_RUN",
                "PUBLIC_SCORE": {"status": "HOLD"},
            },
            "duration_seconds": round(time.time() - started, 3),
            "failures": [f"{type(error).__name__}: {str(error)}"],
        }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

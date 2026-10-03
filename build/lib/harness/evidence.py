"""Tamper-evident evidence bundles.

`seal` writes SHA256SUMS for every file in a run folder (compatible with
`sha256sum -c`). With a key it also writes an Ed25519 signature over that file,
so a published verdict can link to a bundle anyone can verify.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                               Ed25519PublicKey)

SUMS, SIG, PUB = "SHA256SUMS", "SHA256SUMS.sig", "signing-key.pub"
_BUNDLE_FILES = {SUMS, SIG, PUB}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _files(run_dir: Path) -> list[Path]:
    return sorted(p for p in run_dir.rglob("*")
                  if p.is_file() and p.relative_to(run_dir).as_posix() not in _BUNDLE_FILES)


def keygen(key_path: Path) -> Path:
    key_path = Path(key_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_path.chmod(0o600)
    pub = key_path.with_suffix(".pub")
    pub.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return pub


def seal(run_dir: Path, key_path: Path | None = None) -> Path:
    run_dir = Path(run_dir)
    sums = "".join(f"{_sha256(p)}  {p.relative_to(run_dir).as_posix()}\n" for p in _files(run_dir))
    (run_dir / SUMS).write_text(sums)
    if key_path:
        key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
        (run_dir / SIG).write_bytes(key.sign(sums.encode()))
        (run_dir / PUB).write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return run_dir / SUMS


def verify(run_dir: Path, pubkey_path: Path | None = None) -> list[str]:
    """Returns a list of problems; empty means the bundle verifies.

    Pass the publisher's public key from a trusted channel. The copy inside the
    bundle only proves internal consistency, not who signed it.
    """
    run_dir = Path(run_dir)
    problems = []
    sums_path = run_dir / SUMS
    if not sums_path.exists():
        return [f"{SUMS} missing"]
    sums = sums_path.read_text()
    listed = {}
    for line in sums.splitlines():
        digest, rel = line.split("  ", 1)
        listed[rel] = digest
    actual = {p.relative_to(run_dir).as_posix(): p for p in _files(run_dir)}
    for rel, digest in listed.items():
        if rel not in actual:
            problems.append(f"missing: {rel}")
        elif _sha256(actual[rel]) != digest:
            problems.append(f"modified: {rel}")
    problems += [f"unlisted: {rel}" for rel in actual if rel not in listed]

    sig_path = run_dir / SIG
    pub_path = Path(pubkey_path) if pubkey_path else run_dir / PUB
    if sig_path.exists():
        pub = serialization.load_pem_public_key(pub_path.read_bytes())
        assert isinstance(pub, Ed25519PublicKey)
        try:
            pub.verify(sig_path.read_bytes(), sums.encode())
        except InvalidSignature:
            problems.append("signature does not match SHA256SUMS")
    elif pubkey_path:
        problems.append(f"{SIG} missing")
    return problems

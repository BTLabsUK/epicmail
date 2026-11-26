#!/usr/bin/env python3
"""Sign a file the way Epicmail and Epic Wallet releases are signed: minisign's format (ED,
Ed25519 over BLAKE2b-512 of the file) with the BT Labs release key, an unencrypted PKCS#8 PEM.
Called by `tools/ship --publish`. The key id is the first 8 bytes of SHA-256 of the raw public
key; minisign prints it byte-reversed (key id 250522661E0CB33E for 3eb30c1e66220525).

  tools/ship-sign.py FILE SIG TRUSTED_COMMENT [KEY]   (KEY default ~/.config/epicmail/release-signing.key)

The signature has no timestamp, so the same file and key give the same bytes. Verify with
`minisign -Vm FILE -x SIG -P <key pinned in tools/get.sh>`.
"""
import base64
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main(argv):
    if len(argv) not in (4, 5):
        sys.exit(__doc__)
    file, out, trusted = Path(argv[1]), Path(argv[2]), argv[3]
    path = Path(argv[4]) if len(argv) == 5 else Path.home() / ".config/epicmail/release-signing.key"
    if path.stat().st_mode & 0o077:
        sys.exit(f"ship-sign: {path} is readable by group/other; chmod 600 it")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception:  # never echo key material
        sys.exit(f"ship-sign: {path} is not a readable unencrypted PKCS#8 PEM key")
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit(f"ship-sign: {path} is not an Ed25519 key")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyid = hashlib.sha256(raw).digest()[:8]
    sig = key.sign(hashlib.blake2b(file.read_bytes(), digest_size=64).digest())
    glob = key.sign(sig + trusted.encode())
    out.write_text(
        f"untrusted comment: signature from BT Labs key {keyid.hex()}\n"
        f"{base64.b64encode(b'ED' + keyid + sig).decode()}\n"
        f"trusted comment: {trusted}\n"
        f"{base64.b64encode(glob).decode()}\n"
    )


main(sys.argv)

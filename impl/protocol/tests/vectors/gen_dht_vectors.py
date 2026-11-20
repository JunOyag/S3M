#!/usr/bin/env python3
"""Vecteurs de network.dht-directory (spec V3) — générateur.

Écrit `dht_expected.rs` (même répertoire), consommé par tests/dht.rs. Valeurs
calculées par `cryptography` (indépendante du code testé). Régénérer depuis la
racine du dépôt :
    python impl/protocol/tests/vectors/gen_dht_vectors.py
"""
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

OUT = Path(__file__).with_name("dht_expected.rs")
L = lambda x: len(x).to_bytes(4, "big") + x

FX = {
    "SIG_SEED": bytes([0x11]) * 32,
    "SIG_PAYLOAD": b"payload-test",
    "BLOB_KEY": bytes([0x22]) * 32,
    "BLOB_NONCE": bytes([0x33]) * 12,
    "BLOB_PLAINTEXT": b"clair",
    "OFFSET_ID": bytes([0x44]) * 32,
    "K_ATTACH": bytes([0x55]) * 32,
}
SIG_LABEL = b"s3m/sig/user-entry/v1"
BLOB_LABEL = b"dht-user-plaintext"

sk = Ed25519PrivateKey.from_private_bytes(FX["SIG_SEED"])
V = {
    "SIG_PUB": sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    "SIGNATURE": sk.sign(L(SIG_LABEL) + FX["SIG_PAYLOAD"]),
    "BLOB": FX["BLOB_NONCE"] + ChaCha20Poly1305(FX["BLOB_KEY"]).encrypt(
        FX["BLOB_NONCE"], FX["BLOB_PLAINTEXT"], L(BLOB_LABEL) + (1).to_bytes(2, "big")),
    "DISPERSAL_DHT_KEY": sha256(FX["K_ATTACH"]).digest(),
    "EMERGENCY_DHT_KEY": sha256(FX["K_ATTACH"] + b"emergency").digest(),
}
offset = int.from_bytes(sha256(FX["OFFSET_ID"]).digest(), "big") % 2_592_000

lines = ["// FICHIER GÉNÉRÉ — gen_dht_vectors.py (bibliothèque `cryptography`). NE PAS ÉDITER.",
         "#[allow(dead_code)]", "mod generated {"]
lines += [f'    pub const FX_{k}_HEX: &str = "{v.hex()}";' for k, v in FX.items()]
lines += [f'    pub const {k}_HEX: &str = "{v.hex()}";' for k, v in V.items()]
lines += [f"    pub const OFFSET_S: u64 = {offset};", "}", "use generated::*;", ""]
OUT.write_text("\n".join(lines), encoding="utf-8")
print(f"écrit : {OUT}")

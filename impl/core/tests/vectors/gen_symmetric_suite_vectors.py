#!/usr/bin/env python3
"""Vecteurs de composition de la convention KDF V3 et de la suite symétrique — générateur.

Écrit `symmetric_suite_expected.rs` (même répertoire), consommé via `include!`
par les tests de `impl/core` (symmetric-suite, k-attach, k-block, k-dispersal,
k-self, k-node-self, master-key-chain).

RÈGLES :
- Les valeurs attendues sont calculées par la bibliothèque `cryptography`
  (indépendante du code Rust testé) — jamais par s3m-core.
- Le fichier généré est committé ; ce script n'est JAMAIS exécuté par les
  tests Rust (régénération manuelle uniquement).
- Les fixtures d'entrée sont exportées dans le fichier généré (`FX_*`) :
  les tests Rust les lisent de là, elles n'existent qu'à un seul endroit.

Convention (docs/03-crypto/symmetric-suite.md, § KDF) :
    KDF(secret, label, salt, entrées…) = HKDF-SHA256(IKM = secret, salt,
        info = "s3m/kdf/v1" ‖ L(label) ‖ L(entrée_1) ‖ …, 32 o)
    L(x) = u32 big-endian(len(x)) ‖ x

Régénérer, depuis la racine du dépôt :
    python impl/core/tests/vectors/gen_symmetric_suite_vectors.py
"""
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OUT = Path(__file__).with_name("symmetric_suite_expected.rs")

# --- Fixtures d'entrée -----------------------------------------------------
FX = {
    "SECRET": bytes(range(0x00, 0x20)),
    "MASTER_KEY": bytes(range(0x00, 0x20)),
    "ENC_SALT": bytes(range(0xA0, 0xB0)),           # 16 o
    "NODE_SALT": bytes(range(0xB0, 0xC0)),          # 16 o (sel d'IndexNode)
    "ATTACH_SALT": bytes(range(0xD0, 0xE0)),        # 16 o
    "K_ATTACH": bytes(range(0x40, 0x60)),
    "PRIV_USER": bytes(range(0x60, 0x80)),
    "PUB_USER": bytes(range(0x80, 0xA0)),
    "PRIV_NODE": bytes(range(0xC0, 0xE0)),
    "PROTO_HEADER": (1).to_bytes(2, "big"),
    "WRAP_PLAINTEXT": bytes(range(0x40, 0x60)),
    "BLOCK_NONCE": bytes(range(0xE0, 0xEC)),        # nonce de test (aléatoire en production)
    # RFC 7748 §6.1 : clé privée d'Alice, clé publique de Bob.
    "X25519_PRIV": bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
    "X25519_PUB": bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
}
BLOCK_INDEX = 7
VW, VC = 1, 2
BLOCK_PREFIX = "contenu de bloc test s3m".encode("ascii")
BLOCK_LEN, BLOCK_CLEAR_LEN = 65536, 65506

PREFIX = b"s3m/kdf/v1"


def L(x: bytes) -> bytes:
    return len(x).to_bytes(4, "big") + x


def kdf(secret: bytes, label: str, salt: bytes = b"", *inputs: bytes) -> bytes:
    info = PREFIX + L(label.encode()) + b"".join(L(i) for i in inputs)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt or None, info=info).derive(secret)


u16 = lambda v: v.to_bytes(2, "big")
u32 = lambda v: v.to_bytes(4, "big")

V = {}
V["KDF_GENERIC"] = kdf(FX["SECRET"], "test-label", b"salt", b"a", b"bc")
V["KDF_GENERIC_SWAPPED"] = kdf(FX["SECRET"], "test-label", b"salt", b"ab", b"c")
V["K_WRAP"] = kdf(FX["MASTER_KEY"], "master-key-wrap", b"", u16(VW), u16(VC))
wrap_aad = FX["PROTO_HEADER"] + b"master-key-wrap" + u16(VW) + u16(VC)
V["WRAP_CT"] = ChaCha20Poly1305(V["K_WRAP"]).encrypt(b"\x00" * 12, FX["WRAP_PLAINTEXT"], wrap_aad)
assert len(V["WRAP_CT"]) == 48

shared = X25519PrivateKey.from_private_bytes(FX["X25519_PRIV"]).exchange(
    X25519PublicKey.from_public_bytes(FX["X25519_PUB"]))
V["X25519_SHARED"] = shared
V["K_ATTACH"] = kdf(shared, "attach", FX["ATTACH_SALT"])
V["SIG_PRIV_DISPERSAL"] = kdf(FX["K_ATTACH"], "dispersal-signing")
V["K_DISPERSAL_CONTENT"] = kdf(FX["K_ATTACH"], "dispersal-content")
V["K_DISPERSAL_BLOCK"] = kdf(V["K_DISPERSAL_CONTENT"], "dispersal-block", FX["NODE_SALT"])
V["K_SELF"] = kdf(FX["PRIV_USER"], "attachment-recovery")
V["K_NODE_SELF"] = kdf(FX["PRIV_NODE"], "node-recovery")
V["USER_DHT_KEY"] = kdf(FX["PRIV_USER"], "dht-lookup", b"", FX["PUB_USER"])
V["SIG_PRIV_USER_SEED"] = kdf(FX["PRIV_USER"], "dht-signing", b"", FX["PUB_USER"])
V["K_BLOCK"] = kdf(FX["MASTER_KEY"], "block", FX["ENC_SALT"], u32(BLOCK_INDEX))

clear = BLOCK_PREFIX + b"\x00" * (BLOCK_CLEAR_LEN - len(BLOCK_PREFIX))
frame = FX["PROTO_HEADER"] + FX["BLOCK_NONCE"] + ChaCha20Poly1305(V["K_BLOCK"]).encrypt(
    FX["BLOCK_NONCE"], clear, FX["PROTO_HEADER"])
assert len(frame) == BLOCK_LEN
V["BLOCK_FRAME_SHA256"] = sha256(frame).digest()
V["BLOCK_FRAME_TAIL"] = frame[-48:]

lines = [
    "// FICHIER GÉNÉRÉ — gen_symmetric_suite_vectors.py (bibliothèque `cryptography`).",
    "// NE PAS ÉDITER À LA MAIN. Régénérer, depuis la racine du dépôt :",
    "//     python impl/core/tests/vectors/gen_symmetric_suite_vectors.py",
    "//",
    "// Valeurs calculées par une bibliothèque indépendante du code testé.",
    "// Fixtures d'entrée : FX_* ; valeurs attendues : *_HEX.",
    "#[allow(dead_code)]",
    "mod generated {",
]
for k, v in FX.items():
    lines.append(f'    pub const FX_{k}_HEX: &str = "{v.hex()}";')
lines += [f"    pub const FX_BLOCK_INDEX: u32 = {BLOCK_INDEX};",
          f'    pub const FX_BLOCK_PREFIX: &[u8] = b"{BLOCK_PREFIX.decode()}";']
for k, v in V.items():
    lines.append(f'    pub const {k}_HEX: &str = "{v.hex()}";')
lines += ["}", "#[allow(unused_imports)]", "use generated::*;", ""]
OUT.write_text("\n".join(lines), encoding="utf-8")
print(f"écrit : {OUT} ({OUT.stat().st_size} octets)")

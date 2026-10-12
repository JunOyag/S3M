#!/usr/bin/env python3
"""Vecteurs de composition de crypto.symmetric-suite — générateur.

Écrit `symmetric_suite_expected.rs` (même répertoire), consommé par
`impl/core/tests/symmetric_suite_vectors.rs` via `include!`.

RÈGLES :
- Les valeurs attendues sont calculées par la bibliothèque `cryptography`
  (indépendante du code Rust testé) — jamais par p2p-storage-core.
- Le fichier généré est committé ; ce script n'est JAMAIS exécuté par les
  tests Rust (régénération manuelle uniquement, cf. ci-dessous).
- Les fixtures ci-dessous (entrées seules) sont identiques à celles de
  `tests/symmetric_suite_vectors.rs` : toute modification doit être faite
  aux deux endroits.

Régénérer, depuis la racine du dépôt :
    python impl/core/tests/vectors/gen_symmetric_suite_vectors.py
"""
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

OUT = Path(__file__).with_name("symmetric_suite_expected.rs")

# --- Fixtures (entrées seulement, JAMAIS valeurs attendues) ---------------
# Identiques à tests/symmetric_suite_vectors.rs.
MASTER_KEY = bytes(range(32))                    # 000102…1f
K_ENC = bytes(range(0x20, 0x40))                 # 202122…3f
ENC_SALT = b"p2p-enc-salt-v1"
VERSION_WRAPPEE = 1
VERSION_COURANTE = 2
# En-tête de version (2 o) : u16 gros-boutiste de la version de protocole,
# valeur de test 0x0001 — l'encodage réel de l'en-tête est porté par
# deploiement.formats-serialisation (hors périmètre de cet id).
PROTO_HEADER = (1).to_bytes(2, "big")
WRAP_PLAINTEXT = bytes(range(0x40, 0x60))        # 404142…5f (clé wrappée fictive)
BLOCK_PLAINTEXT = "contenu de bloc test p2p-storage".encode("ascii")

LABEL_NONCE = b"p2p-storage/synthetic-nonce/v1"
LABEL_WRAP = b"p2p-storage/master-key-wrap/v1"
LABEL_BLOCK = b"p2p-storage/block/v1"
CTX_WRAP = b"master-key-wrap"
CTX_BLOCK = b"block"


def canonical(*components: bytes) -> bytes:
    """Encodage canonique (spec § KDF) : u32 gros-boutiste || composante."""
    out = b""
    for c in components:
        out += len(c).to_bytes(4, "big") + c
    return out


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    # salt b"" = « sans sel » de la spec (sel par défaut du RFC 5869).
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    h = HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()


# --- Dérivations -----------------------------------------------------------
k_nonce = hkdf_sha256(K_ENC, b"", LABEL_NONCE, 32)
k_wrap = hkdf_sha256(
    MASTER_KEY,
    b"",
    canonical(LABEL_WRAP, VERSION_WRAPPEE.to_bytes(2, "big"), VERSION_COURANTE.to_bytes(2, "big")),
    32,
)
# Étiquette unique passée brute en info (pas d'encodage canonique — une seule
# composante, cf. arbitrage de la passe code).
k_block = hkdf_sha256(MASTER_KEY, ENC_SALT, LABEL_BLOCK, 32)

# --- Nonce synthétique + trames AEAD --------------------------------------
block_aad = PROTO_HEADER + CTX_BLOCK
synth_nonce = hmac_sha256(k_nonce, canonical(block_aad) + BLOCK_PLAINTEXT)[:12]

wrap_aad = (
    PROTO_HEADER
    + CTX_WRAP
    + VERSION_WRAPPEE.to_bytes(2, "big")
    + VERSION_COURANTE.to_bytes(2, "big")
)
wrap_ct = ChaCha20Poly1305(k_wrap).encrypt(b"\x00" * 12, WRAP_PLAINTEXT, wrap_aad)
assert len(wrap_ct) == 32 + 16, "wrapped_key = 32 o chiffrés + 16 o de tag, sans en-tête"

block_payload = ChaCha20Poly1305(k_block).encrypt(synth_nonce, BLOCK_PLAINTEXT, block_aad)
block_frame = synth_nonce + block_payload
assert len(block_frame) == 12 + len(BLOCK_PLAINTEXT) + 16, "trame bloc = nonce + chiffré + tag"

# --- Écriture du fichier Rust ---------------------------------------------
header = """// FICHIER GÉNÉRÉ — gen_symmetric_suite_vectors.py (bibliothèque `cryptography`).
// NE PAS ÉDITER À LA MAIN. Régénérer, depuis la racine du dépôt :
//     python impl/core/tests/vectors/gen_symmetric_suite_vectors.py
//
// Valeurs calculées par une bibliothèque indépendante du code testé
// (p2p-storage-core) ; fixtures d'entrée identiques à
// tests/symmetric_suite_vectors.rs. Ne pas confondre avec les vecteurs RFC
// bruts, qui sont codés en dur dans tests/symmetric_suite_vectors.rs.

"""

body = f"""pub const K_NONCE_HEX: &str = "{k_nonce.hex()}";
pub const K_WRAP_HEX: &str = "{k_wrap.hex()}";
pub const K_BLOCK_HEX: &str = "{k_block.hex()}";
pub const SYNTH_NONCE_HEX: &str = "{synth_nonce.hex()}";
pub const WRAP_CT_HEX: &str = "{wrap_ct.hex()}";
pub const BLOCK_FRAME_HEX: &str = "{block_frame.hex()}";
"""

OUT.write_text(header + body, encoding="utf-8")
print(f"écrit : {OUT} ({OUT.stat().st_size} octets)")

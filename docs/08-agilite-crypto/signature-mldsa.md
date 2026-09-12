---
id: agilite.signature-mldsa
kind: narrative
title: "Signature : Remplacement Direct (Ed25519 → ML-DSA)"
section: "§8.3"
status: draft
verified_by: []
---

# Signature : Remplacement Direct (Ed25519 → ML-DSA)

Contrairement à `K_attach`
([`agilite.k-attach-kem`](k-attach-kem.md)), les mécanismes de signature
(`sig_priv_user`, `sig_priv_dispersal`, `priv_node_recovery` — voir
[`network.dht-directory`](../01-network-dht/dht-directory.md) et
[`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md))
ne changent pas de structure : ML-DSA reste un schéma de signature
classique, et le patron « dériver un seed via KDF puis générer une paire
déterministe » reste valable (ML-DSA supporte un keygen déterministe depuis
un seed, FIPS 204).

Seul impact notable : la taille des clés et signatures croît
significativement (clé publique ~2,6 Ko, signature ~3,3 Ko pour ML-DSA-65,
contre 32/64 octets en Ed25519) — à budgéter dans le dimensionnement des
entrées DHT et des en-têtes FlatBuffers, voir
[`deploiement.formats-serialisation`](../07-deploiement/formats-serialisation.md).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->

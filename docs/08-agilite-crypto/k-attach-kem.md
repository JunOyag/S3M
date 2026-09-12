---
id: agilite.k-attach-kem
kind: narrative
title: "Redesign de K_attach en mode KEM"
section: "§8.2"
status: draft
verified_by: []
---

# Redesign de K_attach en mode KEM

Le `salt` actuel ([`node.AttachedUser`](../02-schemas/node/AttachedUser.md))
devient le véhicule naturel pour porter aussi ce ciphertext :

```
# Connecteur (Initiator) — à l'attachement uniquement :
(shared_secret, kem_ciphertext) = ML-KEM.Encapsulate(pub_node_kem)
K_attach = KDF(shared_secret, salt)

# Nœud (Responder) — à tout moment, y compris après coup :
shared_secret = ML-KEM.Decapsulate(priv_node_kem, kem_ciphertext)
K_attach = KDF(shared_secret, salt)
```

`kem_ciphertext` est stocké aux côtés de `salt`, une seule fois à
l'attachement — le Nœud peut ensuite redériver `K_attach` par simple
décapsulation locale, sans nouvel échange.

## Asymétrie de re-dérivation

Avec le NIKE actuel ([`agilite.kem-vs-nike`](kem-vs-nike.md)), chaque partie
recalcule `K_attach` à tout moment. Avec un KEM, ce n'est plus vrai côté
**Initiator** (le Connecteur) : `Encapsulate` produit un secret aléatoire à
chaque appel, impossible à retrouver sans l'avoir conservé. Cette propriété
est exploitée ailleurs côté Connecteur (migration, chemin de secours,
`K_dispersal_content`) : sans correctif, le Connecteur perdrait la capacité
de relire ses propres anciens attachements.

**Correctif — persistance du secret, façon `master_key_chain`** : le
Connecteur conserve aussi `shared_secret`, wrappé sous `K_self` et ajouté à
l'historique `attachments`, sur le même principe de re-wrap plat que
[`crypto.master-key-chain`](../03-crypto/master-key-chain.md). Le tuple
`attachments` s'étend, de façon additive, à `{node_id, salt, timestamp,
inactivity_detected_at, wrapped_shared_secret}`. Ce correctif ne s'applique
qu'en mode KEM/hybride — voir
[`agilite.tag-hybride`](tag-hybride.md#key_algorithm).

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->

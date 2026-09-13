"""
Scénario : Nœud seul injoignable, partenaires/réseau disponibles.
Réf. protocole : §3.12.4 (EmergencyManifest) + §6 (ligne 2).
"""

SPEC_REF = "§3.12.4, §6 (ligne 2)"
EXPECTED = (
    "Écriture dispersée directement chez des partenaires de proximité "
    "(sélection XOR sur l'identité User, pas Node), sans erasure coding, "
    "n_secours=4 partenaires par défaut. EmergencyManifest publié en DHT, "
    "jamais le DispersalManifest (seul le Nœud peut le signer, §3.9). "
    "Réintégration automatique et mécanique au retour du Nœud, quota "
    "respecté, aucune mutation référençant un bloc absent."
)
WAIT_SECONDS = 45


def inject() -> None:
    # TODO Phase 2+ : bloquer UNIQUEMENT le trafic vers node-host (iptables/
    # tc dans le conteneur réseau, ou règle Docker network) tout en laissant
    # les partenaires joignables — distinct du scénario précédent qui coupe
    # tout. Déclencher une écriture côté Connecteur pendant ce blocage.
    raise NotImplementedError


def assert_recovery() -> tuple[bool, list[str]]:
    # TODO Phase 2+ :
    #  1. vérifier qu'un EmergencyManifest a bien été publié (requête DHT
    #     directe sur emergency_dht_key)
    #  2. débloquer node-host
    #  3. vérifier réintégration + suppression de l'EmergencyManifest +
    #     tombstone envoyé aux partenaires de secours
    raise NotImplementedError

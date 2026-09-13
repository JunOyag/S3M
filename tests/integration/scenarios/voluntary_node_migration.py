"""
Scénario : changement volontaire de Nœud hébergeur (migration).
Réf. protocole : §3.7.1 (migration) + §6 (ligne 6).
"""

SPEC_REF = "§3.7.1, §6 (ligne 6)"
EXPECTED = (
    "Aucune coopération de l'ancien Nœud requise. Le Connecteur re-dérive "
    "l'ancien K_attach pour lire dispersal_root_hash/partners uniquement, "
    "transmet dispersal_root_hash + dispersal_root_partners + "
    "K_dispersal_content au nouveau Nœud (jamais K_attach ni "
    "sig_priv_dispersal). Le nouveau Nœud récupère seul les fragments et "
    "reconstruit. L'ancienne entrée DispersalManifest devient orpheline."
)
WAIT_SECONDS = 60


def inject() -> None:
    # TODO Phase 2+ : démarrer un second Nœud (node-host-2, à ajouter au
    # compose), déclencher une migration via le Connecteur pendant que
    # node-host (l'ancien) reste PLEINEMENT joignable (cas volontaire, pas
    # perte — distinct de node_lost_no_compromise.py).
    raise NotImplementedError


def assert_recovery() -> tuple[bool, list[str]]:
    # TODO Phase 2+ :
    #  1. vérifier que tous les fichiers sont lisibles depuis node-host-2
    #  2. vérifier qu'une nouvelle entrée DHT DispersalManifest existe, sous
    #     sig_pub_dispersal du nouveau Nœud
    #  3. vérifier que node-host (l'ancien) n'a reçu AUCUNE requête
    #     d'écriture/lecture de contenu déchiffré pendant la migration
    #     (seul le Connecteur a manipulé l'ancien K_attach)
    raise NotImplementedError

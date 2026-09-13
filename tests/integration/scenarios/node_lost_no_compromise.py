"""
Scénario : Nœud définitivement perdu (panne matérielle), sans compromission,
avec continuité d'écriture pendant la reconstruction.
Réf. protocole : §5.2 point 6 + §6 (ligne 8).
"""

SPEC_REF = "§5.2 (point 6), §6 (ligne 8)"
EXPECTED = (
    "Nouveau node_id dérivé de la même seed BIP-39. Reconstruction vers les "
    "MÊMES partenaires (pas de nouvelle relation de troc à zéro) — soldes "
    "PartnerAccount transférés tels quels. Pendant la reconstruction, les "
    "écritures utilisent l'espace de secours (EmergencyManifest, §3.12.4) "
    "en priorité (partenaires joignables par construction), avec repli "
    "WriteQueue si le réseau manque aussi. migration_pointer signé par "
    "priv_node_recovery une fois détecté."
)
WAIT_SECONDS = 90  # scénario le plus long : implique reconstruction complète


def inject() -> None:
    # TODO Phase 2+ : docker compose kill -s SIGKILL node-host puis
    # supprimer son volume nommé (perte totale, pas une simple panne
    # réseau) - distinct de node_temporarily_unavailable.py. Démarrer un
    # node-host-recovery utilisant la même seed. Tenter une écriture
    # pendant la fenêtre de reconstruction.
    raise NotImplementedError


def assert_recovery() -> tuple[bool, list[str]]:
    # TODO Phase 2+ :
    #  1. vérifier que node-host-recovery reconstruit bien sa copie locale
    #     intégrale depuis les partenaires
    #  2. vérifier que les MÊMES 12 partenaires sont utilisés (comparer aux
    #     partner_id de l'ancien DispersalManifest)
    #  3. vérifier que l'écriture tentée pendant la fenêtre a bien transité
    #     par EmergencyManifest, pas par une WriteQueue locale
    raise NotImplementedError

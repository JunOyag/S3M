"""
Scénario : Nœud temporairement indisponible.
Réf. protocole : §3.12 (chemin de secours lecture) + §3.12.2 (WriteQueue) + §6.
"""

SPEC_REF = "§3.12, §3.12.2, §6 (ligne 1)"
EXPECTED = (
    "Lecture des fichiers déjà dispersés reste possible via reconstruction "
    "k-parmi-N chez les partenaires (lecture seule). Une écriture tentée "
    "pendant la panne est mise en WriteQueue locale côté Connecteur, sans "
    "modifier fs_root_hash. Au retour du Nœud, la WriteQueue est rejouée "
    "strictement dans l'ordre d'horodatage et purgée au fur et à mesure des "
    "confirmations."
)
WAIT_SECONDS = 30


def inject() -> None:
    # TODO Phase 2+ : docker compose pause node-host (pas kill — on simule une
    # indisponibilité temporaire, pas une perte de disque). Écrire un fichier
    # via le Connecteur pendant la pause (doit atterrir en WriteQueue).
    raise NotImplementedError("À implémenter une fois impl/connector expose une commande d'écriture")


def assert_recovery() -> tuple[bool, list[str]]:
    # TODO Phase 2+ :
    #  1. docker compose unpause node-host
    #  2. attendre la resynchronisation (poll état Connecteur)
    #  3. vérifier que le fichier écrit pendant la panne est bien présent et
    #     lisible via le chemin normal (§3.12), pas seulement via le chemin
    #     de secours
    #  4. vérifier que la WriteQueue locale est vide après resynchronisation
    raise NotImplementedError

"""
Scénario : bloc de données local corrompu côté Nœud (bit-rot simulé).
Réf. protocole : §3.12.1 (vérification côté Connecteur) + §5.4 (scrubbing) + §6 (ligne 3).
"""

SPEC_REF = "§3.12.1, §5.4, §6 (ligne 3)"
EXPECTED = (
    "Le Connecteur détecte l'incohérence de hash à la lecture, retente une "
    "fois, puis reconstruit via k fragments de parité chez les partenaires. "
    "Si la reconstruction produit un hash correct : erreur critique évitée, "
    "incident signalé au Nœud qui répare sa copie locale. Si irrécupérable "
    "(< k fragments valides) : erreur critique explicite nommant le fichier."
)
WAIT_SECONDS = 20


def inject() -> None:
    # TODO Phase 2+ : après une écriture normale réussie, altérer directement
    # un octet du fichier de bloc sur le volume node-host-data (bypass du
    # protocole — simule bit-rot disque, pas une attaque réseau).
    raise NotImplementedError


def assert_recovery() -> tuple[bool, list[str]]:
    # TODO Phase 2+ :
    #  1. déclencher une lecture du fichier concerné via le Connecteur
    #  2. vérifier que le contenu retourné est correct malgré la corruption
    #     locale (reconstruction transparente)
    #  3. vérifier qu'un incident a été journalisé côté Nœud (§3.12.1)
    #  4. relire une seconde fois : la copie locale du Nœud doit être
    #     auto-réparée (§5.4), donc plus besoin de reconstruction
    raise NotImplementedError

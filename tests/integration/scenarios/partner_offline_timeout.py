"""
Scénario : un partenaire hébergeant des fragments de parité tombe hors-ligne
simplement (timeout, pas fraude).
Réf. protocole : §4.2 (volatilité, réparation préventive) + §6 (ligne 4).
"""

SPEC_REF = "§4.2, §6 (ligne 4)"
EXPECTED = (
    "Analyse de disponibilité détecte l'absence. Si le nombre de fragments "
    "de parité disponibles descend vers le seuil k, réparation préventive : "
    "reconstruction locale depuis la copie des k blocs de données, "
    "réémission vers un nouveau partenaire. PAS de blacklist (distinct du "
    "scénario de fraude)."
)
WAIT_SECONDS = 60  # couvre au moins un cycle d'analyse de volatilité


def inject() -> None:
    # TODO Phase 2+ : docker compose stop partner-03 (arrêt propre, pas de
    # réponse PoS incorrecte — juste une absence).
    raise NotImplementedError


def assert_recovery() -> tuple[bool, list[str]]:
    # TODO Phase 2+ :
    #  1. vérifier que le PartnerAccount de partner-03 n'apparaît PAS dans
    #     blacklisted_partners du NodeManifest (distinction critique avec le
    #     scénario de fraude)
    #  2. vérifier qu'un nouveau partenaire (parmi les 11 restants) héberge
    #     désormais le fragment manquant
    raise NotImplementedError

"""
Scénario : un partenaire répond incorrectement à un challenge PoS (fraude).
Réf. protocole : §5.3 (rupture de confiance & blacklist) + §6 (ligne 5).
"""

SPEC_REF = "§5.3, §6 (ligne 5)"
EXPECTED = (
    "Réponse PoS incorrecte -> rupture bilatérale IMMÉDIATE (pas de cycle "
    "d'analyse quotidienne). Destruction locale de toutes les données "
    "hébergées pour ce partenaire, sur TOUTES les relations de troc "
    "actives (portée Nœud<->Partenaire, pas par utilisateur/fichier). "
    "Blacklist permanente, locale, jamais diffusée sur la DHT. Réparation "
    "proactive immédiate des fragments qui lui avaient été confiés."
)
WAIT_SECONDS = 15  # doit être quasi-immédiat, contrairement au timeout simple


def inject() -> None:
    # TODO Phase 2+ : nécessite une image partenaire "malveillante" dédiée
    # (variante de build avec ROLE=partner-fraudulent qui répond
    # délibérément un hash incorrect aux challenges PoS) — pas la même image
    # que les partenaires légitimes.
    raise NotImplementedError


def assert_recovery() -> tuple[bool, list[str]]:
    # TODO Phase 2+ :
    #  1. vérifier que le partenaire fraudeur apparaît dans
    #     blacklisted_partners IMMÉDIATEMENT (pas après le délai de §4.2)
    #  2. vérifier qu'AUCUNE nouvelle dispersion ne lui est jamais confiée
    #     ensuite (tenter une nouvelle écriture, vérifier son absence de la
    #     table Partner résultante)
    #  3. vérifier la réparation proactive des fragments qu'il hébergeait
    raise NotImplementedError

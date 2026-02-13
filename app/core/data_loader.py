import json
from typing import Any, Dict, List

from app.core.config import DATA_DIR


def load_json_list(filename: str) -> List[Dict[str, Any]]:
    """
    Charge une liste d'objets JSON depuis le dossier DATA_DIR.
    Gère les erreurs d'existence et de formatage de manière silencieuse.
    """
    path = DATA_DIR / filename

    # Si le fichier n'existe pas, on renvoie une liste vide
    if not path.exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # On s'assure que c'est bien une liste
            if isinstance(data, list):
                return data
            return []
    except Exception:
        # En cas de JSON corrompu ou erreur I/O
        return []


def load_cms_rules() -> List[Dict[str, Any]]:
    """
    Charge les règles de détection CMS.
    Délègue directement à load_json_list pour faciliter le mocking dans les tests.
    """
    return load_json_list("cms_rules.json")


def load_cve_db() -> List[Dict[str, Any]]:
    """
    Charge la base de vulnérabilités CVE.
    """
    return load_json_list("wp_cves.json")

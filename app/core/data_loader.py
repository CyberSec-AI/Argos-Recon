import json
import logging
from typing import Any, Dict, List

from app.core.config import DATA_DIR

logger = logging.getLogger("recon_assistant")


def load_json_list(filename: str) -> List[str]:
    """Charge une liste de strings non vides. Strip auto."""
    path = DATA_DIR / filename
    if not path.exists():
        logger.debug(f"File {filename} not found, using defaults.")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            logger.error(f"Invalid format in {filename}: expected list")
            return []

        valid_items = []
        skipped_count = 0
        for item in data:
            s = str(item).strip()
            if s:
                valid_items.append(s)
            else:
                skipped_count += 1

        if skipped_count > 0:
            logger.debug(f"Skipped {skipped_count} empty/invalid entries in {filename}")

        return valid_items

    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in {filename}")
        return []
    except Exception as e:
        logger.error(f"Error loading {filename}: {str(e)}")
        return []


def load_cms_rules() -> List[Dict[str, Any]]:
    """Charge les règles CMS. Garantie sans mutation in-place."""
    path = DATA_DIR / "cms_rules.json"
    if not path.exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            logger.error("cms_rules.json must be a list")
            return []

        valid_rules = []
        for i, rule in enumerate(data):
            if not isinstance(rule, dict):
                continue

            if "name" not in rule or not isinstance(rule["name"], str):
                logger.warning(f"Rule #{i} skipped: invalid 'name'")
                continue

            indicators = rule.get("indicators")
            if not isinstance(indicators, list) or not indicators:
                continue

            valid_indicators = [ind for ind in indicators if isinstance(ind, dict)]

            if valid_indicators:
                clean_name = rule["name"].strip()
                new_rule = dict(rule, name=clean_name, indicators=valid_indicators)
                valid_rules.append(new_rule)

        return valid_rules

    except Exception as e:
        logger.error(f"Error loading cms_rules.json: {str(e)}")
        return []


# C'EST CETTE FONCTION QUI MANQUAIT :
def load_cve_db() -> List[Dict[str, Any]]:
    """Charge la base de données CVE WordPress."""
    path = DATA_DIR / "wp_cves.json"
    if not path.exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            else:
                logger.error("wp_cves.json must be a list")
                return []
    except Exception as e:
        logger.error(f"Error loading wp_cves.json: {str(e)}")
        return []

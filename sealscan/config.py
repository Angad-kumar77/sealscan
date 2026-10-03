"""Loading of the optional .sealscan.json configuration file."""
import json
from pathlib import Path
from typing import Any, Dict

from sealscan.models import SEVERITY_ORDER

CONFIG_FILENAME = ".sealscan.json"
ALLOWED_KEYS = {"ignore", "disable_rules", "min_severity", "fail_on"}


class ConfigError(Exception):
    pass


def _string_list(cfg: Dict[str, Any], key: str) -> None:
    value = cfg.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError("'%s' must be a list of strings" % key)


def load_config(path: Path) -> Dict[str, Any]:
    """Load and validate a config file. Returns {} when the file is missing."""
    if not path.is_file():
        return {}
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError("Cannot read %s: %s" % (path, exc))
    if not isinstance(cfg, dict):
        raise ConfigError("%s must contain a JSON object" % path)
    unknown = set(cfg) - ALLOWED_KEYS
    if unknown:
        raise ConfigError("Unknown config keys: " + ", ".join(sorted(unknown)))
    _string_list(cfg, "ignore")
    _string_list(cfg, "disable_rules")
    for key in ("min_severity", "fail_on"):
        if key in cfg and cfg[key] not in SEVERITY_ORDER:
            raise ConfigError("'%s' must be one of: %s" % (key, ", ".join(SEVERITY_ORDER)))
    return cfg

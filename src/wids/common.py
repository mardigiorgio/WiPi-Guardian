from loguru import logger
import yaml, pathlib, os

def setup_logging():
    logger.remove()
    logger.add(lambda m: print(m, end=""), level="INFO")
    return logger

def load_config(path: str) -> dict:
    """
    Load YAML config and normalize paths:
    - Expands env vars and ~ in string paths
    - Resolves relative paths relative to the config file directory
    """
    p = pathlib.Path(path).resolve()
    cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    # Normalize database.path if present
    try:
        db = cfg.setdefault("database", {})
        db_path = db.get("path")
        if isinstance(db_path, str) and db_path:
            # Expand environment variables and user home
            expanded = os.path.expandvars(os.path.expanduser(db_path))
            resolved = pathlib.Path(expanded)
            # If the path is relative, make it relative to the config file dir
            if not resolved.is_absolute():
                resolved = (p.parent / resolved).resolve()
            db["path"] = str(resolved)
    except Exception:
        # keep config as-is if normalization fails
        pass

    return cfg

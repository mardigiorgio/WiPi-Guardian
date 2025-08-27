from loguru import logger
import yaml, pathlib

def setup_logging():
    logger.remove()
    logger.add(lambda m: print(m, end=""), level="INFO")
    return logger

def load_config(path: str) -> dict:
    p = pathlib.Path(path)
    return yaml.safe_load(p.read_text(encoding="utf-8"))

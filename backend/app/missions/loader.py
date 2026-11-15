"""
YAML loader and catalog registry for NO ENTRY missions.
"""

from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional
import yaml

from backend.app.config import settings
from backend.app.missions.models import MissionDefinition


def _missions_dir() -> Path:
    return settings.MISSIONS_DIR


@lru_cache(maxsize=1)
def _load_catalog() -> Dict[str, MissionDefinition]:
    missions: List[MissionDefinition] = []
    data_dir = _missions_dir()
    if data_dir.exists():
        for path in sorted(data_dir.glob("*.yaml")):
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            mission = MissionDefinition(**raw)
            missions.append(mission)

    missions.sort(key=lambda m: m.order)
    return {m.id: m for m in missions}


def reload_missions() -> Dict[str, MissionDefinition]:
    _load_catalog.cache_clear()
    return _load_catalog()


def list_missions() -> List[MissionDefinition]:
    return list(_load_catalog().values())


def get_mission(mission_id: str) -> Optional[MissionDefinition]:
    return _load_catalog().get(mission_id)


"""Shared helpers for loading detection units from the repository."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

# Repository root, resolved relative to this file (automation/_common.py).
REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"


@dataclass
class Detection:
    """A single detection unit loaded from a detections/<name>/ folder."""
    path: Path
    metadata: dict

    @property
    def id(self) -> str:
        return self.metadata.get("id", self.path.name)

    @property
    def name(self) -> str:
        return self.metadata.get("name", self.path.name)

    @property
    def attack(self) -> list[dict]:
        return self.metadata.get("attack", []) or []


def load_detections(detections_dir: Path = DETECTIONS_DIR) -> list[Detection]:
    """Load every detection unit that contains a metadata.yml file."""
    detections: list[Detection] = []
    if not detections_dir.exists():
        return detections
    for meta_file in sorted(detections_dir.glob("*/metadata.yml")):
        with meta_file.open(encoding="utf-8") as fh:
            metadata = yaml.safe_load(fh) or {}
        detections.append(Detection(path=meta_file.parent, metadata=metadata))
    return detections

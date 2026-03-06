import json
import os
from pathlib import Path
from typing import Dict, List, Optional


class WordlistRegistry:
    def __init__(self, registry_path: str = "./data/wordlists.json"):
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.registry_path.exists():
            self.registry_path.write_text("[]", encoding="utf-8")

    def list_wordlists(self) -> List[Dict]:
        return self._load()

    def register_wordlist(self, name: str, path: str, description: str = "") -> Dict:
        absolute_path = str(Path(path).expanduser().resolve())
        if not os.path.exists(absolute_path):
            raise ValueError(f"Path does not exist: {absolute_path}")
        if not os.path.isfile(absolute_path):
            raise ValueError(f"Path is not a file: {absolute_path}")

        items = self._load()
        existing = next((item for item in items if item["name"] == name), None)
        metadata = {
            "name": name,
            "path": absolute_path,
            "description": description,
            "size_bytes": os.path.getsize(absolute_path),
        }
        if existing:
            existing.update(metadata)
        else:
            items.append(metadata)
        self._save(items)
        return metadata

    def remove_wordlist(self, name: str) -> Optional[Dict]:
        items = self._load()
        keep = [item for item in items if item["name"] != name]
        removed = next((item for item in items if item["name"] == name), None)
        self._save(keep)
        return removed

    def _load(self) -> List[Dict]:
        try:
            return json.loads(self.registry_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def _save(self, items: List[Dict]):
        self.registry_path.write_text(json.dumps(items, indent=2), encoding="utf-8")

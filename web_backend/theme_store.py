"""Qt-free access to the legacy ``Color_env.txt`` file.

The web server must be able to start without installing PyQt.  The desktop theme
module imports ``QColor`` at module import time, so this small adapter deliberately
keeps the compatible KEY=#RRGGBB storage format without importing the GUI toolkit.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.paths import COLOR_ENV_PATH

DEFAULTS = {
    "UI_Background": "#FFFFFF",
    "UI_Surface": "#FFFFFF",
    "UI_Surface_Soft": "#F8FBFD",
    "UI_Surface_Muted": "#F3F8FC",
    "Card_Border": "#EEF5FF",
    "Card_Title_Text": "#0863E2",
    "Primary_Blue": "#0863E2",
    "Primary_Blue_Dark": "#054FB8",
    "Primary_Blue_Hover": "#1F75EF",
    "Primary_Blue_Light": "#EAF3FF",
    "Input_Border": "#CFE0FB",
    "Table_Selection_Background": "#EEF5FF",
    "Table_Selection_Text": "#0863E2",
    "Table_Header_Background": "#F3F8FC",
    "Table_Header_Text": "#0863E2",
}
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def _normalize(value: str, fallback: str) -> str:
    value = str(value or "").strip()
    if not value.startswith("#") and len(value) == 6:
        value = f"#{value}"
    return value.upper() if HEX_COLOR.fullmatch(value) else fallback


def load_color_env(path: str | Path = COLOR_ENV_PATH) -> dict[str, str]:
    values = dict(DEFAULTS)
    file_path = Path(path)
    if file_path.exists():
        for line in file_path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            values[key] = _normalize(value, values.get(key, "#000000"))
    return values


def save_color_env(config: dict[str, str], path: str | Path = COLOR_ENV_PATH) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(dict.fromkeys([*DEFAULTS, *config]))
    lines = ["# UI Color Settings", "# Format: KEY=#RRGGBB", ""]
    for key in keys:
        fallback = DEFAULTS.get(key, "#000000")
        lines.append(f"{key}={_normalize(config.get(key, fallback), fallback)}")
    file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ensure_color_env_file(path: str | Path = COLOR_ENV_PATH) -> dict[str, str]:
    config = load_color_env(path)
    if not Path(path).exists():
        save_color_env(config, path)
    return config

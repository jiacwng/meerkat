# Reads the TOML file that says which columns and classification words an incident CSV uses.

import tomllib
from dataclasses import dataclass
from pathlib import Path

from core.incidents import CLASSIFICATIONS, COLUMNS

PRESET_DIR = Path(__file__).parent / "data" / "mappings"
PRESETS = tuple(sorted(path.stem for path in PRESET_DIR.glob("*.toml")))
OPEN = "open"


class MappingError(ValueError):
    pass


@dataclass(frozen=True)
class Mapping:
    name: str
    columns: dict[str, str]
    classifications: dict[str, str]


def load_mapping(name_or_path: str) -> Mapping:
    if name_or_path in PRESETS:
        path, name = PRESET_DIR / f"{name_or_path}.toml", name_or_path
    else:
        path, name = Path(name_or_path), Path(name_or_path).name
        if not path.exists():
            raise MappingError(
                f"{path}: no such mapping; presets are {', '.join(PRESETS)}")
    try:
        table = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError) as error:
        raise MappingError(f"{path}: not a readable file ({error})") from None
    except tomllib.TOMLDecodeError as error:
        raise MappingError(f"{path}: not valid TOML ({error})") from None
    for key in table:
        if key not in ("columns", "classifications"):
            raise MappingError(f"{path}: unknown table {key!r}, expected columns or "
                               "classifications")
    return Mapping(name, _columns(path, table.get("columns", {})),
                   _classifications(path, table.get("classifications", {})))


def _columns(path: Path, given: dict) -> dict[str, str]:
    for key, value in given.items():
        if key not in COLUMNS:
            raise MappingError(f"{path}: [columns] has unknown column {key!r}")
        if not isinstance(value, str) or not value:
            raise MappingError(f"{path}: [columns] {key} must be a non empty string")
    columns = {name: given.get(name, name) for name in COLUMNS}
    readers: dict[str, str] = {}
    for name, source in columns.items():
        if source in readers:
            raise MappingError(f"{path}: {readers[source]} and {name} both read "
                               f"column {source!r}")
        readers[source] = name
    return columns


def _classifications(path: Path, given: dict) -> dict[str, str]:
    for key in given:
        if key not in (*CLASSIFICATIONS, OPEN):
            raise MappingError(f"{path}: [classifications] has unknown key {key!r}")
    owner: dict[str, str] = {}
    for key in (*CLASSIFICATIONS, OPEN):
        listed = given.get(key, [] if key == OPEN else [key])
        if not isinstance(listed, list) or not all(
                isinstance(word, str) and word for word in listed):
            raise MappingError(f"{path}: [classifications] {key} must be a list of non empty "
                               "strings")
        for word in listed:
            if word in owner:
                raise MappingError(
                    f"{path}: classification word {word!r} is listed under {owner[word]} and {key}")
            owner[word] = key
    return {word: "" if key == OPEN else key for word, key in owner.items()}

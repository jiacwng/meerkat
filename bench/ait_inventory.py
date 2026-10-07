# Converts the official AIT-ADS asset inventories (YAML) into the JSON the product
# reads. Needs PyYAML, which the product does not depend on:
#   python -m bench.ait_inventory SOURCE_DIR OUTPUT_DIR

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


def import_ait_inventory(source_path: Path, output_path: Path) -> None:
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    assets = []
    for item in source.values():
        groups = [str(group) for group in item.get("groups", [])]
        if "attacker" in groups:
            continue
        assets.append({
            "hostname": str(item["hostname"]),
            "ip_addresses": [str(ip) for ip in item["ipv4_addresses"]],
            "groups": groups,
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"company": source_path.stem, "assets": assets}, indent=2),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert official AIT inventories")
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    for source_path in sorted(args.source_dir.glob("*.yaml")):
        import_ait_inventory(
            source_path,
            args.output_dir / f"{source_path.stem}.json",
        )


if __name__ == "__main__":
    main()

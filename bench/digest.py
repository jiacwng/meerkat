# Digest the normalized frame so a change can be checked without a full run.
# Identical rows in means an identical queue out, so bench.evaluate is only worth
# its eight folds when this number moves.

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from core.normalize import normalize_scenario

# recorded on main at 2a89055, russellmitchell, 36358 rows over 52 columns
KNOWN = "4b390168afda96bf"


def frame_digest(raw_dir: Path, labels: Path, scenario: str, inventory: Path) -> str:
    frame = normalize_scenario(raw_dir, labels, scenario, inventory)
    frame = frame.sort_values(list(frame.columns), kind="stable").reset_index(drop=True)
    # frozensets and categoricals serialise in hash order, so compare as text
    flat = frame.astype(str).to_csv(index=False).encode()
    return hashlib.sha256(flat).hexdigest()[:16]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Digest a scenario's normalized frame. Nothing downstream can "
                    "change while this stays the same.",
    )
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--labels", type=Path, default=Path("data/labels.csv"))
    parser.add_argument("--scenario", default="russellmitchell")
    parser.add_argument("--inventory", type=Path, default=None)
    parser.add_argument("--expect", default=KNOWN, help="digest to compare against")
    args = parser.parse_args()

    inventory = args.inventory or args.raw_dir / "inventory" / f"{args.scenario}.json"
    digest = frame_digest(args.raw_dir, args.labels, args.scenario, inventory)
    print(f"{args.scenario} {digest}")
    if args.expect and digest != args.expect:
        print(f"moved from {args.expect}; bench.evaluate has to be re-run")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

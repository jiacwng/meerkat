# Fits the model bundle the product ships. It reads all eight benchmark
# environments, seven of which are not in the repository, so it only runs after
# the download described in bench/README.md.

from __future__ import annotations

import argparse
from pathlib import Path

from bench.evaluate import (
    SCENARIOS,
    build_bundle,
    load_inventories,
    load_scenarios,
    prepare_sessions,
)
from core.classifier import save_model


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m bench.train",
        description="fit the Meerkat model bundle on the AIT-ADS benchmark",
    )
    parser.add_argument("--holdout", help="environment to keep out of training")
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument("--labels", type=Path, default=Path("data/labels.csv"))
    parser.add_argument(
        "--inventory-dir", type=Path, default=Path("data/raw/inventory")
    )
    parser.add_argument(
        "--event-csv-dir", type=Path, default=Path("data/raw/alerts_csv")
    )
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--model", type=Path, default=Path("models/meerkat_bundle.skops")
    )
    args = parser.parse_args(argv)

    scenarios = tuple(s for s in SCENARIOS if s != args.holdout)
    print(
        f"training on {len(scenarios)} environments"
        + (f", holding out {args.holdout}" if args.holdout else "")
    )
    frames = load_scenarios(
        args.raw_dir, args.labels, args.inventory_dir, scenarios,
        args.event_csv_dir,
    )
    inventories = load_inventories(args.inventory_dir, scenarios)
    sessions = prepare_sessions(frames, inventories)
    bundle = build_bundle(sessions, n_estimators=args.trees, seed=args.seed)
    save_model(bundle, args.model)
    print(f"saved {args.model} ({args.trees} trees, seed {args.seed})")


if __name__ == "__main__":
    main()

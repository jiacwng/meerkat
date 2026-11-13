# The meerkat command line: queue, review, inspect and runs.

import argparse
import json
import shutil
import sys
from pathlib import Path

from meerkat import __version__

EXIT_ERROR = 1
GRADE_CODES = {
    "tp": "TruePositive",
    "bp": "BenignPositive",
    "fp": "FalsePositive",
}
DEFAULT_LIMIT = 20


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "queue" and args.file is not None and args.run is not None:
        parser.error("queue takes a FILE or --run, not both")

    # pandas loads here so that --help and --version stay instant
    from core.incidents import IncidentError
    from core.store import StoreError

    try:
        args.handler(args)
    except (IncidentError, StoreError, OSError) as error:
        print(f"meerkat: error: {_printable(str(error))}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR) from None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meerkat",
        description="Rank a SOC's open incidents and learn from the grades "
                    "analysts give.")
    parser.add_argument("--version", action="version", version=f"meerkat {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    queue = sub.add_parser("queue", help="score an incident CSV, or reopen a run")
    queue.add_argument("file", nargs="?", type=Path, metavar="FILE",
                       help="incident CSV to score and save as a new run")
    shown = queue.add_mutually_exclusive_group()
    shown.add_argument("--limit", type=_positive, default=DEFAULT_LIMIT, metavar="N",
                       help=f"rows shown (default {DEFAULT_LIMIT})")
    shown.add_argument("--all", action="store_true", help="every row instead of the first N")
    queue.add_argument("--closed", action="store_true",
                       help="incidents under the close level instead of the queue")
    _add_run(queue)
    _add_json(queue)
    _add_runs_dir(queue)
    queue.set_defaults(handler=_queue)

    review = sub.add_parser("review", help="record the grade of an incident")
    review.add_argument("incident", metavar="INCIDENT")
    review.add_argument("grade", choices=tuple(GRADE_CODES), metavar="GRADE",
                        help="tp (true positive), bp (benign positive) or "
                             "fp (false positive)")
    review.add_argument("--note", default="", metavar="TEXT",
                        help="free text stored with the grade")
    _add_runs_dir(review)
    review.set_defaults(handler=_review)

    inspect = sub.add_parser("inspect", help="show one incident")
    inspect.add_argument("incident", metavar="INCIDENT")
    _add_run(inspect)
    _add_json(inspect)
    _add_runs_dir(inspect)
    inspect.set_defaults(handler=_inspect)

    runs = sub.add_parser("runs", help="list saved runs")
    _add_json(runs)
    _add_runs_dir(runs)
    runs.set_defaults(handler=_runs)
    return parser


def _add_run(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", metavar="ID", help="run id (default: the latest)")


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="machine readable output")


def _add_runs_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"), metavar="PATH",
                        help="where runs and grades are kept (default runs/)")


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError("expected a whole number above 0")
    return value


def _queue(args: argparse.Namespace) -> None:
    from core import close, store
    from core.incidents import read_incidents

    if args.file is not None:
        incidents = read_incidents(args.file)
        meta = store.save_run(args.runs_dir, incidents, args.file.name)
    else:
        meta, incidents = store.load_run(args.runs_dir, args.run)

    # the rule's past rate comes from every run, the rows shown from this one
    scored, level, entries = _scored(args.runs_dir)
    in_run = scored["IncidentId"].isin(incidents["IncidentId"])
    open_incidents = scored[in_run & (scored["IncidentGrade"] == "")]
    closed = open_incidents[open_incidents["pile"] == "closed"]
    audit = open_incidents[open_incidents["pile"] == "audit"]
    if args.closed:
        listed = closed
    else:
        listed = open_incidents[open_incidents["pile"] != "closed"]
    shown = listed if args.all else listed.head(args.limit)

    if args.json:
        rows = [_as_record(row, position)
                for position, row in enumerate(shown.to_dict("records"), start=1)]
        _print_json({
            "run": meta["run"], "open": len(open_incidents), "closed": len(closed),
            "audit": len(audit), "close_level": level, "miss_rate": close.MISS_RATE,
            "audit_share": close.AUDIT_SHARE, "queue": rows})
        return

    if open_incidents.empty:
        print(f"No open incidents in run {meta['run']}.")
        return
    if not listed.empty:
        rows = [
            (str(position), row["IncidentId"], f"{row['score']:.2f}",
             "audit" if row["pile"] == "audit" else "", row["DetectorId"],
             _rule_history(row), row["Timestamp"], row["AlertTitle"])
            for position, row in enumerate(shown.to_dict("records"), start=1)]
        _print_table(("#", "incident", "score", "pile", "rule", "rule history", "time",
                      "title"), rows)
        print(f"{len(shown)} of {len(listed)} open incidents, run {meta['run']}")
    if level is None and len(entries) >= close.needed():
        print("Nothing closed: too many graded true positives share the lowest score.")
    elif level is None:
        print(f"Nothing closed yet: {len(entries)} of {close.needed()} "
              "graded true positives.")
    else:
        print(f"{len(closed)} more are under the close level "
              f"(at most {close.MISS_RATE:.0%} of true positives). "
              f"{len(audit)} others under it are above as audit.")


def _review(args: argparse.Namespace) -> None:
    from core import close, store

    scored, level, _ = _scored(args.runs_dir)
    found = scored[scored["IncidentId"] == args.incident]
    if found.empty:
        raise store.StoreError(f"no incident {args.incident!r} in {args.runs_dir}")
    reviews = store.read_reviews(args.runs_dir)
    earlier = reviews[reviews["IncidentId"] == args.incident]
    if earlier.empty:
        score = float(found["score"].iloc[0])
        pile = close.pile_of(args.incident, score, level)
    else:
        score, pile = float(earlier["score"].iloc[0]), earlier["pile"].iloc[0]
    grade = GRADE_CODES[args.grade]
    store.append_grade(args.runs_dir, args.incident, grade, args.note, score, pile)
    print(f"{_printable(args.incident)} graded {grade}")


def _scored(runs_dir: Path):
    from core import close, rank, store

    reviews = store.read_reviews(runs_dir)
    scored = rank.score(store.load_history(runs_dir))
    entries = close.calibration(scored, reviews)
    level = close.close_level(entries)
    return close.place(scored, reviews, level), level, entries


def _inspect(args: argparse.Namespace) -> None:
    from core import store
    from core.incidents import DESCRIPTIVE, LINKS, SEPARATOR

    scored, _, _ = _scored(args.runs_dir)
    if args.run is not None:
        _, in_run = store.load_run(args.runs_dir, args.run)
        scored = scored[scored["IncidentId"].isin(in_run["IncidentId"])]
    found = scored[scored["IncidentId"] == args.incident]
    if found.empty:
        raise store.StoreError(f"no incident {args.incident!r} in {args.runs_dir}")
    row = found.iloc[0].to_dict()

    if args.json:
        record = _as_record(row)
        for column in ("MitreTechniques", *LINKS):
            record[column] = [v for v in row[column].split(SEPARATOR) if v]
        _print_json(record)
        return

    lines = [
        ("incident", row["IncidentId"]),
        ("time", row["Timestamp"]),
        ("rule", row["DetectorId"]),
        *((name, row[name]) for name in DESCRIPTIVE),
        ("MitreTechniques", row["MitreTechniques"].replace(SEPARATOR, ", ")),
        ("grade", row["IncidentGrade"] or "open"),
        ("score", f"{row['score']:.2f}"),
        ("pile", row["pile"]),
        ("rule history", _rule_history(row)),
        *((name, row[name].replace(SEPARATOR, ", ")) for name in LINKS),
    ]
    for name, value in lines:
        if value:
            print(f"{name:<16} {_printable(value)}")


def _runs(args: argparse.Namespace) -> None:
    from core import store

    runs = store.list_runs(args.runs_dir)
    if args.json:
        _print_json(runs)
        return

    if not runs:
        print(f"No runs in {args.runs_dir}.")
        return
    rows = [(meta["run"], meta["created"], str(meta["incidents"]), meta["source"])
            for meta in runs]
    _print_table(("run", "created", "incidents", "source"), rows)


def _rule_history(row: dict) -> str:
    if row["rule_graded"] == 0:
        return "never graded"
    return f"{row['rule_true_positives']} of {row['rule_graded']} true positive"


def _as_record(row: dict, position: int | None = None) -> dict:
    record = dict(row)
    record["score"] = round(float(row["score"]), 4)
    record["rule_graded"] = int(row["rule_graded"])
    record["rule_true_positives"] = int(row["rule_true_positives"])
    if position is not None:
        record = {"position": position, **record}
    return record


def _print_json(value) -> None:
    print(json.dumps(value, indent=2))


def _print_table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    rows = [tuple(_printable(cell) for cell in row) for row in rows]
    widths = [max(len(cell) for cell in column) for column in zip(header, *rows, strict=True)]
    # on a terminal a long last column is cut at the edge; a pipe gets every character
    edge = shutil.get_terminal_size().columns if sys.stdout.isatty() else None
    for line in (header, *rows):
        cells = (cell.ljust(width) for cell, width in zip(line, widths, strict=True))
        print("  ".join(cells).rstrip()[:edge])


# incident text is untrusted: control and escape characters never reach the terminal
def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in text)

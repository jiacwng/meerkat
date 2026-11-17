# The meerkat command line: queue, review, inspect, runs and config.

import argparse
import json
import os
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
    if args.command == "queue" and args.file is None and args.mapping is not None:
        parser.error("--mapping needs FILE")
    if args.command == "config":
        if (args.setting is None) != (args.value is None):
            parser.error("config takes SETTING and VALUE, or nothing")
        if args.value is not None:
            try:
                args.value = SETTINGS[args.setting](args.value)
            except argparse.ArgumentTypeError as error:
                parser.error(f"{args.setting}: {error}")

    # pandas loads here so that --help and --version stay instant
    from core.incidents import IncidentError
    from core.mapping import MappingError
    from core.store import StoreError

    try:
        args.handler(args)
        sys.stdout.flush()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(EXIT_ERROR) from None
    except (IncidentError, MappingError, StoreError, OSError) as error:
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
    queue.add_argument("--mapping", metavar="NAME_OR_PATH",
                       help="column names and grade words of FILE: defender, sentinel, "
                            "splunk or a TOML file (default defender)")
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

    config = sub.add_parser("config", help="show the settings, or change one")
    config.add_argument("setting", nargs="?", choices=("miss_rate", "keep_linked"),
                        metavar="SETTING", help="miss_rate or keep_linked")
    config.add_argument("value", nargs="?", metavar="VALUE",
                        help="a number between 0 and 1 for miss_rate, true or false "
                             "for keep_linked")
    _add_runs_dir(config)
    config.set_defaults(handler=_config)
    return parser


def _add_run(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", metavar="ID", help="only the incidents of this run")


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="machine readable output")


def _add_runs_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"), metavar="PATH",
                        help="where runs and grades are kept (default runs/)")


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a whole number above 0") from None
    if value < 1:
        raise argparse.ArgumentTypeError("expected a whole number above 0")
    return value


def _rate(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a number between 0 and 1") from None
    if not 0 < value < 1:
        raise argparse.ArgumentTypeError("expected a number between 0 and 1")
    return value


def _flag(text: str) -> bool:
    if text not in ("true", "false"):
        raise argparse.ArgumentTypeError("expected true or false")
    return text == "true"


SETTINGS = {"miss_rate": _rate, "keep_linked": _flag}


def _percent(rate: float) -> str:
    return f"{rate * 100:g}%"


def _queue(args: argparse.Namespace) -> None:
    from core import close, store
    from core.incidents import read_incidents
    from core.mapping import load_mapping

    incoming = None
    run = None
    run_ids = None
    if args.file is not None:
        mapping = load_mapping("defender" if args.mapping is None else args.mapping)
        incoming = read_incidents(args.file, mapping)
    elif args.run is not None:
        _, in_run = store.load_run(args.runs_dir, args.run)
        run = args.run
        run_ids = in_run["IncidentId"]

    scored, level, entries, settings = _scored(args.runs_dir, incoming)
    if incoming is not None:
        run = store.save_run(args.runs_dir, incoming, args.file.name, mapping.name)["run"]
    miss_rate, keep_linked = settings["miss_rate"], settings["keep_linked"]
    open_incidents = scored[scored["IncidentGrade"] == ""]
    if run_ids is not None:
        open_incidents = open_incidents[open_incidents["IncidentId"].isin(run_ids)]
    closed = open_incidents[open_incidents["pile"] == "closed"]
    audit = open_incidents[open_incidents["pile"] == "audit"]
    kept_linked = 0
    if level is not None and keep_linked:
        under = open_incidents[(open_incidents["score"] < level)
                               & (open_incidents["linked_true_positive"] >= 1)]
        kept_linked = len(under)
    if args.closed:
        listed = closed
    else:
        listed = open_incidents[open_incidents["pile"] != "closed"]
    shown = listed if args.all else listed.head(args.limit)

    if args.json:
        rows = [_as_record(row, position)
                for position, row in enumerate(shown.to_dict("records"), start=1)]
        _print_json({
            "run": run, "open": len(open_incidents), "closed": len(closed),
            "audit": len(audit), "close_level": level, "miss_rate": miss_rate,
            "audit_share": close.AUDIT_SHARE, "keep_linked": keep_linked,
            "kept_linked": kept_linked, "queue": rows})
        return

    if open_incidents.empty:
        print("No open incidents." if run_ids is None
              else f"No open incidents in run {run}.")
    else:
        if not listed.empty:
            rows = [
                (str(position), row["IncidentId"], f"{row['score']:.2f}",
                 "audit" if row["pile"] == "audit" else "", row["DetectorId"],
                 _rule_history(row), row["reason"], row["Timestamp"], row["AlertTitle"])
                for position, row in enumerate(shown.to_dict("records"), start=1)]
            _print_table(("#", "incident", "score", "pile", "rule", "rule history", "reason",
                          "time", "title"), rows)
            kind = "set aside" if args.closed else "in the queue"
            where = "" if run_ids is None else f", run {run}"
            print(f"{len(shown)} of {len(listed)} incidents {kind}{where}")
        if level is None and len(entries) >= close.needed(miss_rate):
            lowest = entries[entries["score"] == entries["score"].min()]
            if (lowest["weight"] > 1).any():
                print("Nothing closed: a true positive found in the audit sample counts for ten.")
            else:
                print("Nothing closed: too many graded true positives share the lowest score.")
        elif level is None:
            print(f"Nothing closed yet: {len(entries)} of {close.needed(miss_rate)} "
                  "graded true positives.")
        else:
            if args.closed:
                print(f"In the queue as audit: {len(audit)}")
            else:
                print(f"Set aside under the close level: {len(closed)} "
                      f"(target: at most {_percent(miss_rate)} of true positives)")
                print(f"Shown above as audit: {len(audit)}")
            if kept_linked:
                print(f"Kept in the queue for a link to a true positive: {kept_linked}")


def _config(args: argparse.Namespace) -> None:
    from core import store

    settings = _settings(args.runs_dir)
    if args.setting is None:
        for name, value in settings.items():
            print(_setting_line(name, value))
        return

    previous = settings[args.setting]
    saved = store.read_settings(args.runs_dir)
    saved[args.setting] = args.value
    store.write_settings(args.runs_dir, saved)
    print(_setting_line(args.setting, args.value))
    if previous == args.value:
        return
    if args.setting == "miss_rate":
        print(f"Miss rate changed from {_percent(previous)} to {_percent(args.value)}. "
              "Earlier grades keep the pile they were given.")
    elif args.value:
        print("Incidents linked to a true positive are now kept in the queue.")
    else:
        print("Incidents linked to a true positive can now be closed.")


def _setting_line(name: str, value: float | bool) -> str:
    return f"{name}={str(value).lower()}"


def _settings(runs_dir: Path) -> dict:
    from core import close, store

    return {"miss_rate": close.DEFAULT_MISS_RATE, "keep_linked": close.DEFAULT_KEEP_LINKED,
            **store.read_settings(runs_dir)}


def _review(args: argparse.Namespace) -> None:
    from core import close, store

    scored, level, _, settings = _scored(args.runs_dir)
    found = scored[scored["IncidentId"] == args.incident]
    if found.empty:
        raise store.StoreError(f"no incident {args.incident!r} in {args.runs_dir}")
    reviews = store.read_reviews(args.runs_dir)
    earlier = reviews[reviews["IncidentId"] == args.incident]
    if earlier.empty:
        score = float(found["score"].iloc[0])
        linked = int(found["linked_true_positive"].iloc[0])
        if found["IncidentGrade"].iloc[0] != "":
            pile = "queue"
        else:
            pile = close.pile_of(args.incident, score, level, linked, settings["keep_linked"])
    else:
        score, pile = float(earlier["score"].iloc[0]), earlier["pile"].iloc[0]
    grade = GRADE_CODES[args.grade]
    store.append_grade(args.runs_dir, args.incident, grade, args.note, score, pile)
    print(f"{_printable(args.incident)} graded {grade}")


def _scored(runs_dir: Path, incoming=None):
    from core import close, rank, store

    reviews = store.read_reviews(runs_dir)
    scored = rank.score(store.load_history(runs_dir, incoming))
    settings = _settings(runs_dir)
    entries = close.calibration(scored, reviews)
    level = close.close_level(entries, settings["miss_rate"])
    placed = close.place(scored, reviews, level, settings["keep_linked"])
    return placed, level, entries, settings


def _inspect(args: argparse.Namespace) -> None:
    from core import store
    from core.incidents import DESCRIPTIVE, LINKS, SEPARATOR

    scored, _, _, _ = _scored(args.runs_dir)
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
        ("without links", f"{row['score_without_links']:.2f}"),
        ("as a new rule", f"{row['score_as_new_rule']:.2f}"),
        ("reason", row["reason"]),
        ("pile", row["pile"]),
        ("rule history", _rule_history(row)),
        ("linked incidents", _linked(row)),
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


def _linked(row: dict) -> str:
    if row["linked"] == 0:
        return "none"
    return (f"{row['linked']} earlier ({row['linked_true_positive']} true positive, "
            f"{row['linked_benign_positive']} benign positive, "
            f"{row['linked_false_positive']} false positive)")


def _as_record(row: dict, position: int | None = None) -> dict:
    record = dict(row)
    for column in ("score", "score_without_links", "score_as_new_rule"):
        record[column] = round(float(row[column]), 4)
    for column in ("rule_graded", "rule_true_positives", "linked", "linked_true_positive",
                   "linked_benign_positive", "linked_false_positive"):
        record[column] = int(row[column])
    if position is not None:
        record = {"position": position, **record}
    return record


def _print_json(value) -> None:
    print(json.dumps(value, indent=2))


def _print_table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    rows = [tuple(_printable(cell) for cell in row) for row in rows]
    widths = [max(len(cell) for cell in column) for column in zip(header, *rows, strict=True)]
    # on a terminal only the last column is cut to fit; a pipe gets every character
    fixed = sum(widths[:-1]) + 2 * (len(widths) - 1)
    edge = shutil.get_terminal_size().columns if sys.stdout.isatty() else None
    if edge is not None and edge <= fixed:
        edge = None
    for line in (header, *rows):
        cells = (cell.ljust(width) for cell, width in zip(line, widths, strict=True))
        print("  ".join(cells).rstrip()[:edge])


# incident text is untrusted: control and escape characters never reach the terminal
def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in text)

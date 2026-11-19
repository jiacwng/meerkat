# The meerkat command line: queue, review, inspect, runs, config and serve.

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


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "queue" and args.file is not None and args.run is not None:
        parser.error("queue takes a FILE or --run, not both")
    if args.command == "queue" and args.file is None and args.mapping is not None:
        parser.error("--mapping needs FILE")
    if args.command == "review":
        if args.file is None and (args.incident is None or args.grade is None):
            parser.error("review takes INCIDENT and GRADE, or --file")
        if args.file is not None and (args.incident is not None or args.note):
            parser.error("--file takes no INCIDENT, GRADE or --note")
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
    shown.add_argument("--limit", type=_positive, metavar="N", help="only the first N rows")
    shown.add_argument("--all", action="store_true",
                       help="also the incidents below the budget")
    queue.add_argument("--mapping", metavar="NAME_OR_PATH",
                       help="column names and grade words of FILE: defender, sentinel, "
                            "splunk or a TOML file (default defender)")
    _add_run(queue)
    _add_json(queue)
    _add_runs_dir(queue)
    queue.set_defaults(handler=_queue)

    review = sub.add_parser("review", help="record the grade of an incident, or a file "
                                           "of grades")
    review.add_argument("incident", nargs="?", metavar="INCIDENT")
    review.add_argument("grade", nargs="?", choices=tuple(GRADE_CODES), metavar="GRADE",
                        help="tp (true positive), bp (benign positive) or "
                             "fp (false positive)")
    review.add_argument("--note", default="", metavar="TEXT",
                        help="free text stored with the grade")
    review.add_argument("--file", type=Path, metavar="FILE",
                        help="CSV of grades with the columns IncidentId and IncidentGrade")
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
    config.add_argument("setting", nargs="?", choices=("budget", "sample_share"),
                        metavar="SETTING", help="budget or sample_share")
    config.add_argument("value", nargs="?", metavar="VALUE",
                        help="a whole number above 0 or none for budget, a number from 0 "
                             "up to 1 for sample_share")
    _add_runs_dir(config)
    config.set_defaults(handler=_config)

    serve = sub.add_parser("serve", help="open the queue as a web page on this machine")
    serve.add_argument("--port", type=int, default=0, metavar="N",
                       help="port to listen on (default: a free one)")
    _add_runs_dir(serve)
    serve.set_defaults(handler=_serve)
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


def _budget(text: str) -> int | None:
    return None if text == "none" else _positive(text)


def _share(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a number from 0 up to 1") from None
    if not 0 <= value < 1:
        raise argparse.ArgumentTypeError("expected a number from 0 up to 1")
    return value


SETTINGS = {"budget": _budget, "sample_share": _share}


def _queue(args: argparse.Namespace) -> None:
    from core import budget, store
    from core.incidents import read_incidents
    from core.mapping import load_mapping
    from meerkat import records

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

    settings = records.settings(args.runs_dir)
    scored = records.scored(args.runs_dir, incoming)
    limit = settings["budget"]
    if incoming is not None:
        run = store.save_run(args.runs_dir, incoming, args.file.name, mapping.name)["run"]
        if limit is not None:
            opened = scored.loc[scored["IncidentGrade"] == "", "IncidentId"].tolist()
            sample = budget.draw(opened, limit, settings["sample_share"],
                                 store.read_samples(args.runs_dir))
            if sample["pool"]:
                store.save_sample(args.runs_dir, run, sample)
    record = records.queue(args.runs_dir, scored, settings, run, run_ids)

    reading = record["queue"][:record["to_read"]]
    below = record["queue"][record["to_read"]:]
    listed = record["queue"] if args.all or args.json else reading
    shown = listed if args.limit is None else listed[:args.limit]
    if args.json:
        _print_json({**record, "queue": shown})
        return

    if not record["queue"]:
        print("No open incidents." if run_ids is None
              else f"No open incidents in run {run}.")
        return
    rows = [
        (str(row["position"]), row["IncidentId"], f"{row['score']:.2f}", _mark(row),
         row["DetectorId"], _rule_tp(row),
         f"{row['linked_true_positive']}/{row['linked']}",
         _delta(row["score"] - row["score_as_new_rule"]),
         _delta(row["score"] - row["score_without_links"]),
         row["MitreTechniques"], row["Timestamp"], row["AlertTitle"])
        for row in shown]
    _print_table(("#", "incident", "score", "status", "rule", "rule_tp", "linked_tp",
                  "rule_delta", "link_delta", "mitre", "time", "title"), rows,
                 sum(row["status"] != "below" for row in shown))
    if len(shown) < len(listed):
        print(f"{len(shown)} of {len(listed)} shown")
    total = f"Total: {record['open']}"
    if limit is not None:
        total += f" (to read: {len(reading)}, below the budget: {len(below)})"
    total += f"  budget: {'none' if limit is None else limit}"
    print(total if run_ids is None else f"{total}  run: {run}")
    marks = [_mark(row) for row in below]
    if "linked" in marks or "new rule" in marks:
        print(f"Below the budget: {marks.count('linked')} linked to a true positive, "
              f"{marks.count('new rule')} with a rule never graded")
    if run_ids is None and limit is not None:
        print(_sample_line(record))


def _mark(row: dict) -> str:
    if row["status"] != "below":
        return "sample" if row["status"] == "sample" else ""
    if row["linked_true_positive"] >= 1:
        return "linked"
    return "new rule" if row["rule_graded"] == 0 else ""


def _sample_line(record: dict) -> str:
    sample, unread = record["sample"], record["unread_true_positives"]
    outside = f"{sample['not_sampled']} not sampled"
    if unread is None:
        return f"Sample: {sample['drawn']} drawn, 0 graded, {outside}"
    return (f"Sample: {sample['graded']} graded, {sample['true_positive']} true positive, "
            f"{outside}. Unread true positives: {unread['low']} to {unread['high']} (95%)")


def _config(args: argparse.Namespace) -> None:
    from core import store
    from meerkat import records

    settings = records.settings(args.runs_dir)
    if args.setting is None:
        for name, value in settings.items():
            print(_setting_line(name, value))
        return

    previous = settings[args.setting]
    saved = store.read_settings(args.runs_dir)
    if args.value is None:
        saved.pop(args.setting, None)
    else:
        saved[args.setting] = args.value
    store.write_settings(args.runs_dir, saved)
    print(_setting_line(args.setting, args.value))
    if args.setting == "budget" and previous is None and args.value is not None:
        print("A sample is drawn from the next file given to meerkat queue.")


def _setting_line(name: str, value: float | None) -> str:
    return f"{name}={str(value).lower()}"


def _review(args: argparse.Namespace) -> None:
    from core import budget
    from core.incidents import read_grades
    from meerkat import records

    if args.file is None:
        grades = [(args.incident, GRADE_CODES[args.grade])]
    else:
        grades = read_grades(args.file)
    scored = records.scored(args.runs_dir)
    true_positives = records.grade(args.runs_dir, scored, grades, args.note)
    if args.file is None:
        print(f"{_printable(args.incident)} graded {grades[0][1]}")
        return
    print(f"{len(grades)} incidents graded from {args.file}")
    line = f"True positives: {len(true_positives)}"
    if records.settings(args.runs_dir)["budget"] is not None:
        ranked, sample, below = (true_positives.count(name) for name in budget.STATUSES)
        line += f" (to read: {ranked}, sample: {sample}, below the budget: {below})"
    print(line)


def _inspect(args: argparse.Namespace) -> None:
    from core.incidents import DESCRIPTIVE, LINKS
    from meerkat import records

    scored = records.scored(args.runs_dir)
    record = records.incident(args.runs_dir, scored, args.incident, args.run)
    if args.json:
        _print_json(record)
        return

    lines = [
        ("incident", record["IncidentId"]),
        ("time", record["Timestamp"]),
        ("rule", record["DetectorId"]),
        *((name, record[name]) for name in DESCRIPTIVE),
        ("MitreTechniques", ", ".join(record["MitreTechniques"])),
        ("grade", record["IncidentGrade"] or "open"),
        ("score", f"{record['score']:.2f}"),
        ("without links", f"{record['score_without_links']:.2f}"),
        ("as a new rule", f"{record['score_as_new_rule']:.2f}"),
        ("status", record["status"]),
        ("rule_tp", _rule_tp(record)),
        ("linked", _linked(record)),
        *((name, ", ".join(record[name])) for name in LINKS),
    ]
    for name, value in lines:
        if value:
            print(f"{name:<16} {_printable(value)}")
    if record["linked_incidents"]:
        print()
        _print_table(("linked incident", "grade", "time", "rule", "title"),
                     [tuple(linked[name] for name in records.LINKED_SHOWN)
                      for linked in record["linked_incidents"]])


def _serve(args: argparse.Namespace) -> None:
    from meerkat import web

    web.serve(args.runs_dir, args.port)


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


def _rule_tp(row: dict) -> str:
    return f"{row['rule_true_positives']}/{row['rule_graded']}"


def _linked(row: dict) -> str:
    return (f"{row['linked']} ({row['linked_true_positive']} TP, "
            f"{row['linked_benign_positive']} BP, {row['linked_false_positive']} FP)")


def _delta(value: float) -> str:
    text = f"{value:+.2f}"
    return "0.00" if text[1:] == "0.00" else text


def _print_json(value) -> None:
    print(json.dumps(value, indent=2))


def _print_table(header: tuple[str, ...], rows: list[tuple[str, ...]],
                 first_below: int | None = None) -> None:
    rows = [tuple(_printable(cell) for cell in row) for row in rows]
    widths = [max(len(cell) for cell in column) for column in zip(header, *rows, strict=True)]
    # on a terminal only the last column is cut to fit; a pipe gets every character
    fixed = sum(widths[:-1]) + 2 * (len(widths) - 1)
    edge = shutil.get_terminal_size().columns if sys.stdout.isatty() else None
    if edge is not None and edge <= fixed:
        edge = None
    for number, line in enumerate((header, *rows)):
        if number - 1 == first_below:
            print("Below the budget:")
        cells = (cell.ljust(width) for cell, width in zip(line, widths, strict=True))
        print("  ".join(cells).rstrip()[:edge])


# incident text is untrusted: control and escape characters never reach the terminal
def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in text)

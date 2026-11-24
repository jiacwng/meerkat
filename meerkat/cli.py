# The meerkat command line: queue, review, inspect, runs, config, budget and serve.

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from meerkat import __version__

EXIT_ERROR = 1
STYLES = {"dim": "2", "cyan": "36", "red": "31"}
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
        if args.file is not None and (args.incident is not None or args.comment or args.group):
            parser.error("--file takes no INCIDENT, GRADE, --comment or --group")
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
    review.add_argument("--comment", default="", metavar="TEXT",
                        help="free text stored with the grade")
    review.add_argument("--group", action="store_true",
                        help="also grade the open incidents grouped with INCIDENT")
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

    report = sub.add_parser("budget", help="show what is below the budget and what the "
                                           "sample says about it")
    _add_json(report)
    _add_runs_dir(report)
    report.set_defaults(handler=_budget_report)

    serve = sub.add_parser("serve", help="open the queue as a web page on this machine")
    serve.add_argument("--port", type=_port, default=0, metavar="N",
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


def _port(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a port from 0 to 65535") from None
    if not 0 <= value <= 65535:
        raise argparse.ArgumentTypeError("expected a port from 0 to 65535")
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


def _draw_sample(runs_dir: Path, run: str, settings: dict, scored) -> None:
    from core import budget, groups, store

    if settings["budget"] is None or store.has_sample(runs_dir, run):
        return
    opened = scored.loc[scored["IncidentGrade"] == "", "IncidentId"].tolist()
    samples = store.read_samples(runs_dir)
    lead = groups.leads(scored, budget.drawn_ids(samples))
    sample = budget.draw(opened, settings["budget"], settings["sample_share"], samples, lead)
    if sample["pool"]:
        store.save_sample(runs_dir, run, sample)


def _queue(args: argparse.Namespace) -> None:
    from core import store
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
        _draw_sample(args.runs_dir, run, settings, scored)
    record = records.queue(args.runs_dir, scored, settings, run, run_ids)

    reading = record["queue"][:record["to_read"]]
    below = record["queue"][record["to_read"]:]
    listed = record["queue"] if args.all or args.json else reading
    shown = listed if args.limit is None else listed[:args.limit]
    if args.json:
        _print_json({**record, "queue": shown})
        return

    if record["queue"]:
        rows = [
            (str(row["position"]), row["IncidentId"], f"{row['score']:.2f}",
             str(len(row["members"]) + 1) if row["members"] else "",
             _rule_tp(row), f"{row['linked_true_positive']}/{row['linked']}", row["flag"],
             row["Category"], row["Severity"], row["host"], row["user"],
             _clock(row["latest"]), row["AlertTitle"])
            for row in shown]
        header = ("#", "incident", "score", "group", "rule_tp", "linked_tp", "flag",
                  "category", "severity", "host", "user", "time", "title")
        if not any(row["Severity"] for row in shown):
            at = header.index("severity")
            header = header[:at] + header[at + 1:]
            rows = [row[:at] + row[at + 1:] for row in rows]
        under = [row["placement"] == "below budget" for row in shown]
        styles = ["dim" if low else "cyan" if row["flag"] == "sample" else ""
                  for row, low in zip(shown, under, strict=True)]
        _print_table(header, rows,
                     {"#", "score", "group", "rule_tp", "linked_tp"}, styles,
                     (len(shown) - sum(under), f"below budget {len(below)}"))
        print()
    rows_listed = f"{len(listed)} listed"
    if len(shown) < len(listed):
        rows_listed = f"{len(shown)} of {rows_listed}"
    lines = [("OPEN", f"{record['open']} incidents in {len(record['queue'])} rows, "
                      f"{rows_listed}")]
    if limit is not None:
        marks = [row["flag"] for row in below]
        lines.append(("BELOW BUDGET", f"{len(below)} rows, {marks.count('linked TP')} "
                                      f"linked TP, {marks.count('ungraded rule')} "
                                      "ungraded rule"))
    if run_ids is not None:
        lines.append(("RUN", run))
    for label, value in lines:
        print(f"{label:<12}   {value}")


def _budget_report(args: argparse.Namespace) -> None:
    from meerkat import records

    settings = records.settings(args.runs_dir)
    record = records.queue(args.runs_dir, records.scored(args.runs_dir), settings)
    if args.json:
        _print_json({name: value for name, value in record.items()
                     if name not in ("queue", "grades", "links")})
        return
    if settings["budget"] is None:
        print("BUDGET   not set")
        return

    reading = record["queue"][:record["to_read"]]
    below = record["queue"][record["to_read"]:]
    unread = sum(1 + len(row["members"]) for row in below)
    lines = [("BUDGET", f"{settings['budget']} rows"),
             ("BELOW BUDGET", f"{len(below)} rows, {unread} incidents")]
    if below:
        marks = [row["flag"] for row in below]
        lines += [("  linked TP", str(marks.count("linked TP"))),
                  ("  ungraded rule", str(marks.count("ungraded rule"))),
                  ("  oldest below", _clock(record["below_oldest"]))]
    sample, interval = record["sample"], record["tp_below_budget"]
    graded = f"{sample['drawn']} drawn, {sample['graded']} graded"
    if sample["graded"]:
        graded += f", {sample['true_positive']} TP"
    lines.append(("SAMPLE", graded))
    waiting = [_printable(row["IncidentId"]) for row in reading if row["flag"] == "sample"]
    if waiting:
        lines.append(("  to grade", ", ".join(waiting)))
    if sample["not_sampled"]:
        lines.append(("  not sampled",str(sample["not_sampled"])))
    if interval is None:
        estimated = "not estimated, 0 graded samples"
    elif unread == 0:
        estimated = "not estimated, 0 incidents below budget"
    else:
        estimated = (f"{interval['low']} to {interval['high']} of "
                     f"{unread - sample['not_sampled']}, 95% interval, "
                     f"from {sample['graded']} graded")
    lines.append(("TP BELOW BUDGET", estimated))
    width = max(len(label) for label, _ in lines)
    for label, value in lines:
        print(f"{label:<{width}}   {value}")


def _summary(label: str, values: dict) -> str:
    return f"{label:<6}   " + "   ".join(f"{name} {value}" for name, value in values.items())


def _clock(timestamp: str) -> str:
    return f"{timestamp[5:10]} {timestamp[11:16]}"


def _config(args: argparse.Namespace) -> None:
    from core import store
    from meerkat import records

    settings = records.settings(args.runs_dir)
    if args.setting is None:
        for name, value in settings.items():
            print(_setting_line(name, value))
        return

    saved = store.read_settings(args.runs_dir)
    if args.value is None:
        saved.pop(args.setting, None)
    else:
        saved[args.setting] = args.value
    store.write_settings(args.runs_dir, saved)
    runs = store.list_runs(args.runs_dir)
    if runs:
        newest = runs[-1]["run"]
        scored = records.scored(args.runs_dir)
        graded = set(scored.loc[scored["IncidentGrade"] != "", "IncidentId"])
        if (store.has_sample(args.runs_dir, newest)
                and not graded & set(store.read_samples(args.runs_dir)[-1]["drawn"])):
            store.drop_sample(args.runs_dir, newest)
        _draw_sample(args.runs_dir, newest, records.settings(args.runs_dir), scored)
    print(_setting_line(args.setting, args.value))


def _setting_line(name: str, value: float | None) -> str:
    return f"{name}={str(value).lower()}"


def _review(args: argparse.Namespace) -> None:
    from core import budget
    from core.incidents import read_grades
    from meerkat import records

    scored = records.scored(args.runs_dir)
    kept = {}
    if args.file is not None:
        grades = read_grades(args.file)
    elif args.group:
        together = records.with_group(args.runs_dir, scored, args.incident)
        grades = [(incident, GRADE_CODES[args.grade]) for incident in together]
        kept = {incident: grade for incident, grade
                in records.reviewed_with(args.runs_dir, scored, args.incident).items()
                if grade != GRADE_CODES[args.grade]}
    else:
        grades = [(args.incident, GRADE_CODES[args.grade])]
    true_positives = records.grade(args.runs_dir, scored, grades, args.comment)
    if args.file is None:
        counts = {"incident": _printable(args.incident), "grade": grades[0][1],
                  "incidents": len(grades)}
        before = dict(zip(scored["IncidentId"], scored["IncidentGrade"], strict=True))
        if before[args.incident] not in ("", grades[0][1]):
            counts["replaced"] = before[args.incident]
        print(_summary("GRADED", counts))
        if args.group:
            print("  graded   " + " ".join(_printable(incident) for incident, _ in grades))
        if kept:
            print("  kept     " + ", ".join(f"{_printable(incident)} {grade}"
                                            for incident, grade in kept.items()))
        return
    counts = {"incidents": len(grades), "tp": len(true_positives)}
    if records.settings(args.runs_dir)["budget"] is not None:
        to_read, sample, below = (true_positives.count(name) for name in budget.PLACEMENTS)
        counts.update(tp_to_read=to_read, tp_sample=sample, tp_below=below)
    print(_summary("GRADED", counts))


def _inspect(args: argparse.Namespace) -> None:
    from core.incidents import GRADES
    from meerkat import records

    scored = records.scored(args.runs_dir)
    record = records.incident(args.runs_dir, scored, args.incident, args.run)
    if args.json:
        _print_json(record)
        return

    sections = {
        "INCIDENT": [
            ("incident", record["IncidentId"]),
            ("time", record["Timestamp"]),
            ("rule", record["DetectorId"]),
            ("title", record["AlertTitle"]),
            ("category", record["Category"]),
            ("severity", record["Severity"]),
            ("techniques", ", ".join(record["MitreTechniques"])),
            ("grade", record["IncidentGrade"] or "open"),
            ("placement", record["placement"]),
        ],
        "SCORE": [
            ("score", f"{record['score']:.2f}"),
            *zip(("rule", "linked"), _graded_before(
                (record["rule_true_positives"], record["rule_benign_positives"],
                 record["rule_graded"]),
                (record["linked_true_positive"], record["linked_benign_positive"],
                 record["linked"])), strict=True),
            ("same rule", f"{record['linked_same_rule']} of {record['linked']}"
             if record["linked"] else ""),
        ],
        "GROUP": [("incidents", ", ".join(record["members"]))],
    }
    width = max(len(name) for lines in sections.values() for name, _ in lines)
    for title, lines in sections.items():
        lines = [(name, value) for name, value in lines if value]
        if lines:
            print(title if title == "INCIDENT" else f"\n{title}")
        for name, value in lines:
            print(f"{name:<{width}}  {_printable(value)}")
    red = {GRADES[0]: "red"}
    if record["grade_history"]:
        print("\nHISTORY")
        _print_table(("graded", "grade", "comment"),
                     [(past["time"], past["grade"], past["comment"])
                      for past in record["grade_history"]], set(),
                     [red.get(past["grade"], "") for past in record["grade_history"]])
    if record["entities"]:
        print("\nENTITIES")
        short = ["".join(letter for letter in grade if letter.isupper()) for grade in GRADES]
        _print_table(("entity", "value", "graded_before", *short),
                     [(entity["field"], entity["value"], str(entity["graded_before"]),
                       *(str(entity[grade]) for grade in GRADES))
                      for entity in record["entities"]], {"graded_before", *short},
                     [""] * len(record["entities"]))
    if record["linked_incidents"]:
        print("\nLINKED")
        _print_table(("incident", "grade", "time", "rule", "title"),
                     [tuple(linked[name] for name in records.LINKED_SHOWN)
                      for linked in record["linked_incidents"]], set(),
                     [red.get(linked["IncidentGrade"], "")
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
        print(_summary("RUNS", {"saved": 0}))
        return
    rows = [(meta["run"], meta["created"], str(meta["incidents_in_file"]), meta["file"])
            for meta in runs]
    _print_table(("run", "created", "incidents_in_file", "file"), rows, {"incidents_in_file"},
                 [""] * len(rows))


def _graded_before(*counts: tuple[int, int, int]) -> list[str]:
    cells = [(str(tp), str(bp), str(total - tp - bp), str(total)) for tp, bp, total in counts]
    wide = [max(len(row[at]) for row in cells) for at in range(4)]
    return [f"{tp:>{wide[0]}} TP  {bp:>{wide[1]}} BP  {fp:>{wide[2]}} FP  "
            f"of {total:>{wide[3]}} graded before" for tp, bp, fp, total in cells]


def _rule_tp(row: dict) -> str:
    return f"{row['rule_true_positives']}/{row['rule_graded']}"


def _print_json(value) -> None:
    print(json.dumps(value, indent=2))


def _print_table(header: tuple[str, ...], rows: list[tuple[str, ...]], right: set[str],
                 styles: list[str], divider: tuple[int, str] | None = None) -> None:
    rows = [tuple(_printable(cell) for cell in row) for row in rows]
    widths = [max(len(cell) for cell in column) for column in zip(header, *rows, strict=True)]
    # on a terminal only the last column is cut to fit; a pipe gets every character
    fixed = sum(widths[:-1]) + 2 * (len(widths) - 1)
    terminal = sys.stdout.isatty()
    edge = shutil.get_terminal_size().columns if terminal else None
    if edge is not None and edge <= fixed:
        edge = None
    coloured = terminal and "NO_COLOR" not in os.environ
    upper = tuple(name.upper() for name in header)
    for number, (line, style) in enumerate(zip((upper, *rows), ("", *styles), strict=True)):
        if divider is not None and number - 1 == divider[0]:
            print(f"-- {divider[1]} ".ljust(fixed + widths[-1], "-")[:edge])
        cells = (cell.rjust(width) if name in right else cell.ljust(width)
                 for cell, width, name in zip(line, widths, header, strict=True))
        text = "  ".join(cells).rstrip()[:edge]
        print(f"\x1b[{STYLES[style]}m{text}\x1b[0m" if style and coloured else text)


# incident text is untrusted: control and escape characters never reach the terminal
def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else " " for ch in text)

# a prompt loop over the same views the commands print: type a handle, see the
# view, `b` walks back, `q` quits. No alternate screen, no framework.

from __future__ import annotations

from meerkat import cli


def _show_queue(run, show_all: bool) -> None:
    families = run.families if show_all else run.families[run.families["in_queue"]]
    reviews = cli.current_reviews(run.directory)
    title = "all families" if show_all else "Review queue"
    cli.render_queue(families, reviews, title)


def _prompt_line(family, session_handle) -> str:
    if family is None:
        return "F3=open family   all=every family   queue=budgeted view   q=quit"
    if session_handle is None:
        return ("S1=open session   review benign|false-positive [note]   "
                "b=back   q=quit")
    return ("A1=open alert   review escalate|benign|false-positive [note]   "
            "b=back   q=quit")


def browse_loop(run, input_line=input) -> None:
    import os
    # an exported COLUMNS freezes rich's width; drop it so resizes apply live
    os.environ.pop("COLUMNS", None)
    os.environ.pop("LINES", None)
    cli.hints_enabled = False
    family = None
    session_handle = None
    show_all = False
    _show_queue(run, show_all)
    try:
        while True:
            cli.errors.print(f"[dim]{_prompt_line(family, session_handle)}[/dim]")
            try:
                line = input_line("browse> ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            if not line:
                continue
            word, _, rest = line.partition(" ")
            canon = cli._canon_handle(word)

            if canon in ("Q", "QUIT", "EXIT"):
                return
            if canon in ("B", "BACK"):
                if session_handle is not None:
                    session_handle = None
                    cli.render_family(
                        run, family, cli.current_reviews(run.directory)
                    )
                elif family is not None:
                    family = None
                    _show_queue(run, show_all)
                continue
            if canon in ("ALL", "QUEUE"):
                show_all = canon == "ALL"
                family = None
                session_handle = None
                _show_queue(run, show_all)
                continue
            if word.lower() == "review":
                if family is None:
                    cli.errors.print("[red]open a family first[/red]")
                    continue
                decision, _, note = rest.partition(" ")
                decision = decision.strip().lower()
                if decision == "escalate" and session_handle is None:
                    cli.errors.print(
                        "[red]escalate names a session[/red]  open S1 first"
                    )
                    continue
                allowed = (
                    cli.REVIEW_DECISIONS if session_handle is not None
                    else tuple(
                        d for d in cli.REVIEW_DECISIONS if d != "escalate"
                    )
                )
                if decision not in allowed:
                    cli.errors.print(
                        f"[red]decision must be one of "
                        f"{', '.join(allowed)}[/red]"
                    )
                    continue
                session_key = None
                if session_handle is not None:
                    session = run.session_by_handle(family, session_handle)
                    session_key = cli.session_label_key(session, run.alerts)
                cli.append_review(
                    run.directory, run.run_id, family["family_id"],
                    family["handle"], decision, note.strip(),
                    session_key=session_key, session_handle=session_handle,
                )
                cli.console.print(f"[green]recorded[/green] {decision}")
                continue

            if canon.startswith("F"):
                try:
                    family = run.family_by_handle(canon)
                except KeyError as error:
                    cli.errors.print(f"[red]{error.args[0]}[/red]")
                    continue
                session_handle = None
                cli.render_family(run, family, cli.current_reviews(run.directory))
                continue
            if canon.startswith("S"):
                if family is None:
                    cli.errors.print("[red]open a family first, e.g. F1[/red]")
                    continue
                try:
                    session = run.session_by_handle(family, canon)
                except KeyError as error:
                    cli.errors.print(f"[red]{error.args[0]}[/red]")
                    continue
                session_handle = canon
                alerts = run.session_alerts(session)
                cli.render_session(family, canon, session, alerts)
                cli.render_alert_rows(alerts, 20)
                continue
            if canon.startswith("A"):
                if session_handle is None:
                    cli.errors.print("[red]open a session first, e.g. S1[/red]")
                    continue
                session = run.session_by_handle(family, session_handle)
                alerts = run.session_alerts(session)
                position = int(canon[1:]) if canon[1:].isdigit() else 0
                if not 1 <= position <= len(alerts):
                    cli.errors.print(
                        f"[red]no alert {word}[/red]  "
                        f"{session_handle} holds A1..A{len(alerts)}"
                    )
                    continue
                cli.render_alert_detail(
                    family, session_handle, f"A{position}",
                    alerts.iloc[position - 1],
                )
                continue

            cli.errors.print(
                f"[red]unknown input {word!r}[/red]  handles, review, b, or q"
            )
    finally:
        cli.hints_enabled = True

# Picks the reader of an incident file: Microsoft Graph's JSON answer or a CSV in meerkat's own columns.

import csv
from pathlib import Path

import pandas as pd

from core.defender import read_graph
from core.incidents import IncidentError, read_incidents, read_table


def read(path) -> tuple[pd.DataFrame, str]:
    try:
        with open(path, "rb") as handle:
            start = handle.read(64).lstrip(b"\xef\xbb\xbf \t\r\n")
    except OSError:
        # the reader picked below reports a file that cannot be opened
        start = b""
    if Path(path).suffix.lower() == ".json" or start[:1] in (b"{", b"["):
        return read_graph(path), "defender"
    table = read_table(path)
    if "IncidentId" in table.columns:
        return read_incidents(path, table), "meerkat"
    with open(path, encoding="utf-8-sig", newline="") as handle:
        header = handle.readline()
    for separator in (";", "\t"):
        if "IncidentId" in next(csv.reader([header], delimiter=separator)):
            raise IncidentError(f"{path}: columns are separated by {separator!r}, expected ','")
    raise IncidentError(
        f"{path}: not a Microsoft Graph incidents answer in JSON, nor a CSV with meerkat's "
        "columns IncidentId, Timestamp and DetectorId")

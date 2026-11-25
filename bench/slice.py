# Cuts one organisation out of GUIDE_Train.csv as a demo incident file and a classification key.

import argparse
from pathlib import Path

import pandas as pd
from train import markers, read_guide

from core.incidents import COLUMNS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("guide", type=Path, help="path to GUIDE_Train.csv")
    parser.add_argument("org", help="OrgId to cut")
    parser.add_argument("days", type=int,
                        help="calendar days at the end of the organisation left open")
    parser.add_argument("out", type=Path,
                        help="directory for incidents.csv and classifications.csv")
    args = parser.parse_args()

    blank = markers(read_guide(args.guide))
    wanted = ("OrgId", *COLUMNS)
    chunks = pd.read_csv(args.guide, usecols=lambda name: name in wanted, dtype=str,
                         keep_default_na=False, chunksize=1_000_000)
    rows = pd.concat(chunk[chunk["OrgId"] == args.org] for chunk in chunks)
    rows = rows[[name for name in wanted if name in rows.columns]]

    classified = (rows["IncidentGrade"] != "").groupby(rows["IncidentId"]).transform("any")
    rows = rows[classified].copy()
    for column, values in blank.items():
        rows.loc[rows[column].isin(values), column] = ""
    rows = rows.sort_values("Timestamp", kind="stable")

    day = rows["Timestamp"].str[:10]
    last_days = sorted(day.unique())[-args.days:]
    first_day = day.groupby(rows["IncidentId"]).transform("first")
    open_rows = first_day.isin(last_days)
    classifications = rows.loc[open_rows & (rows["IncidentGrade"] != "")]
    classifications = classifications.drop_duplicates("IncidentId")[["IncidentId", "IncidentGrade"]]
    opened = rows.loc[open_rows, "IncidentId"].drop_duplicates()
    classifications = classifications.set_index("IncidentId").reindex(opened).reset_index()
    rows.loc[open_rows, "IncidentGrade"] = ""

    args.out.mkdir(exist_ok=True)
    rows.to_csv(args.out / "incidents.csv", index=False, lineterminator="\n")
    classifications.to_csv(args.out / "classifications.csv", index=False, lineterminator="\n")
    print(f"{rows['IncidentId'].nunique()} incidents, {len(rows)} rows, "
          f"{len(opened)} open incidents")


if __name__ == "__main__":
    main()

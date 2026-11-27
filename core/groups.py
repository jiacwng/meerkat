# Puts the open incidents of one rule that have identical entity values in one group, led by the top score.

import pandas as pd

from core.incidents import LINKS, SEPARATOR


def leads(scored: pd.DataFrame, apart: set[str]) -> dict[str, str]:
    opened = scored[scored["IncidentGrade"] == ""]
    lead: dict[str, str] = {}
    first: dict[tuple, str] = {}
    for row in opened[["IncidentId", "DetectorId", *LINKS]].to_dict("records"):
        incident = row["IncidentId"]
        entities = tuple((column, value) for column in LINKS
                         for value in row[column].split(SEPARATOR) if value)
        if incident in apart or not entities:
            lead[incident] = incident
        else:
            lead[incident] = first.setdefault((row["DetectorId"], entities), incident)
    return lead

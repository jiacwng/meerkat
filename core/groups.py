# Puts the open incidents of one rule that have identical entity values in one group, led by the top score.

from collections import Counter

import pandas as pd

from core.features import PLACEHOLDER_SHARE
from core.incidents import LINKS, SEPARATOR


def leads(scored: pd.DataFrame, apart: set[str]) -> dict[str, str]:
    values = {row["IncidentId"]: [(column, value) for column in LINKS
                                  for value in row[column].split(SEPARATOR) if value]
              for row in scored[["IncidentId", *LINKS]].to_dict("records")}
    seen = Counter(value for found in values.values() for value in found)
    limit = PLACEHOLDER_SHARE * len(scored)

    opened = scored[scored["IncidentGrade"] == ""]
    lead: dict[str, str] = {}
    first: dict[tuple, str] = {}
    for incident, rule in zip(opened["IncidentId"], opened["DetectorId"], strict=True):
        entities = tuple(value for value in values[incident] if seen[value] <= limit)
        if incident in apart or not entities:
            lead[incident] = incident
        else:
            lead[incident] = first.setdefault((rule, entities), incident)
    return lead

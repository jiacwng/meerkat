# A small incident CSV in GUIDE's column names, shared by the tests.

import csv
import hashlib
from pathlib import Path

HEADER = (
    "OrgId", "IncidentId", "AlertId", "Timestamp", "DetectorId", "AlertTitle",
    "Category", "MitreTechniques", "IncidentGrade", "AccountName", "IpAddress",
)

# rule 7 was graded twice, both true positive; rule 9 twice, never true positive
ROWS = (
    ("1", "100", "a1", "2024-06-01T08:00:00.000Z", "7", "Suspicious sign in",
     "InitialAccess", "T1078;T1078.004", "TruePositive", "alice", "10.0.0.1"),
    ("1", "100", "a2", "2024-06-01T08:05:00.000Z", "9", "Mail forwarding rule",
     "Exfiltration", "T1114", "TruePositive", "alice", "10.0.0.2"),
    ("1", "101", "a3", "2024-06-02T09:00:00.000Z", "7", "Suspicious sign in",
     "InitialAccess", "T1078", "TruePositive", "bob", ""),
    ("1", "102", "a4", "2024-06-03T10:00:00.000Z", "9", "Mail forwarding rule",
     "Exfiltration", "T1114", "BenignPositive", "carol", ""),
    ("1", "103", "a5", "2024-06-04T11:00:00.000Z", "9", "Mail forwarding rule",
     "Exfiltration", "T1114", "FalsePositive", "dave", ""),
    ("1", "200", "a6", "2024-06-05T12:00:00.000Z", "9", "Mail forwarding rule",
     "Exfiltration", "T1114", "", "erin", "10.0.0.9"),
    ("1", "201", "a7", "2024-06-05T13:00:00.000Z", "7", "Suspicious sign in",
     "InitialAccess", "T1078", "", "alice", "10.0.0.1"),
    ("1", "202", "a8", "2024-06-05T14:00:00.000Z", "42", "New rule",
     "Discovery", "", "", "frank", ""),
)


def plain_row(incident_id: str, rule: str, grade: str = "") -> tuple:
    return ("1", incident_id, f"a{incident_id}", "2024-06-10T00:00:00Z", rule, "Title",
            "Category", "", grade, "", "")


# written out here again so that a change to the sampling rule fails a test
def is_sampled(incident_id: str) -> bool:
    digest = hashlib.sha256(incident_id.encode()).hexdigest()
    return int(digest[:8], 16) / 2**32 < 0.10


def sampled_ids(sampled: bool, count: int) -> list[str]:
    found = []
    number = 0
    while len(found) < count:
        number += 1
        if is_sampled(f"o{number}") == sampled:
            found.append(f"o{number}")
    return found


# rule 3 has 20 true positives and rule 9 has 20 false positives, so a rule 9 incident
# scores about 0.13; 20 ungraded rule 7 incidents t0 to t19 are there to be graded
def calibration_rows(audit: int, closed: int) -> tuple:
    rows = [plain_row(f"p{i}", "3", "TruePositive") for i in range(20)]
    rows += [plain_row(f"f{i}", "9", "FalsePositive") for i in range(20)]
    rows += [plain_row(f"t{i}", "7") for i in range(20)]
    rows += [plain_row(i, "9") for i in sampled_ids(True, audit)]
    rows += [plain_row(i, "9") for i in sampled_ids(False, closed)]
    return tuple(rows)


def write_csv(path: Path, rows=ROWS, header=HEADER) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)
    return path

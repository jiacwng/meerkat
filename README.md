# meerkat

Meerkat is a command-line tool that ranks a SOC's open incidents. It reads an
incident export, scores every open incident from the grades analysts gave to
earlier ones, and prints a review queue. Incidents that score low enough are
set aside, and a sample of them is still shown so that the tool can be checked.

![The queue, one incident, and the grades loaded from a file](docs/demo.gif)

## Quick start

Python 3.12 or newer.

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e .
meerkat queue examples/incidents.csv
```

`examples/incidents.csv` is one organisation of Microsoft's GUIDE dataset: 933
incidents over 28 days, of which the 42 from the last three days are open.

```text
#   incident  score  pile  rule  rule history              reason                     time                  title
1   44394     1.00         2     305 of 336 true positive  linked incidents raise it  2024-06-16T03:46:06Z  2
2   76281     1.00         2     305 of 336 true positive  linked incidents raise it  2024-06-16T13:48:53Z  2
...
18  145885    0.76         3     13 of 37 true positive    linked incidents raise it  2024-06-15T23:31:40Z  4
19  54866     0.73         1     4 of 4 true positive      rule history raises it     2024-06-16T19:48:26Z  1
20 of 33 incidents in the queue
Set aside under the close level: 9 (target: at most 5% of true positives)
Shown above as audit: 3
Kept in the queue for a link to a true positive: 5
Kept in the queue for a rule never graded: 2
```

GUIDE replaces rule names and titles with numbers, so the last column is a
number here. `examples/grades.csv` holds the grade Microsoft's customers gave
to each of the 42. Load it to check the queue:

```bash
meerkat review --file examples/grades.csv
```

```text
42 incidents graded from examples/grades.csv
True positives: 20 in the queue, 0 set aside
```

## Commands

| Command | What it does |
| --- | --- |
| `meerkat queue [FILE]` | Scores an incident CSV and saves it as a run. Without FILE it lists the open incidents of every saved run. |
| `meerkat review INCIDENT GRADE` | Records a grade: `tp`, `bp` or `fp`. |
| `meerkat review --file FILE` | Records every grade in a CSV. |
| `meerkat inspect INCIDENT` | Shows one incident with its score, its rule history and its linked incidents. |
| `meerkat runs` | Lists the saved runs. |
| `meerkat config [SETTING VALUE]` | Shows the settings, or changes one. |

`queue --closed` lists the incidents that were set aside. `queue --run ID` lists
one run only. `--json` gives machine readable output on `queue`, `inspect` and
`runs`. Runs, grades and settings are kept in `runs/`, or in the folder given
by `--runs-dir`.

A grade changes the next queue:

```bash
meerkat review 44394 tp --note "confirmed with the user"
meerkat queue
```

## How the score works

The score is a logistic regression on ten inputs. Each input is computed from
incidents earlier in time only:

- how often the incidents of this rule were graded true positive, and how
  many were graded;
- the same two numbers for the whole organisation;
- how many earlier incidents share a device, account, address, file hash or
  URL with this one, counted by grade. For each shared value, the 50 most
  recent earlier incidents are counted.

The weights ship with the package. They were fitted on 424,265 graded
incidents from 4,497 organisations in GUIDE. The `reason` column says which
group of inputs moved the score most, and `inspect` shows the score with the
links removed and with the rule treated as new.

## The close level

Once enough true positives are graded, 19 at the default setting, Meerkat
computes a close level: the highest score under which at most 5% of the graded
true positives fall. Open incidents under it leave the queue. About one in ten
of them, chosen by a hash of the incident id, is kept in the queue as `audit`,
and a true positive found there counts for ten when the level is computed
again.

An incident linked to an earlier graded true positive is never set aside.
Neither is an incident whose rule has never been graded.

## Settings

| Setting | Meaning | Default |
| --- | --- | --- |
| `miss_rate` | Share of true positives accepted under the close level. | 0.05 |
| `keep_linked` | Keep incidents linked to a graded true positive in the queue. | true |

```bash
meerkat config
meerkat config miss_rate 0.02
meerkat config keep_linked false
```

Both are saved in `runs/settings.json` and apply to later commands.

## Your own data

Meerkat reads a CSV with one row per alert, for one organisation, with
ISO 8601 times. It needs three columns: an incident id, a time and a rule id.
A grade column gives it history. The default column names are those of
Microsoft Defender XDR as GUIDE publishes them.

`--mapping` names the columns and grade words of another source:

```bash
meerkat queue export.csv --mapping sentinel
meerkat queue export.csv --mapping site.toml
```

```toml
[columns]
IncidentId = "case_id"
Timestamp = "opened_at"
DetectorId = "rule"
IncidentGrade = "outcome"

[grades]
TruePositive = ["confirmed"]
open = ["new", "in progress"]
```

A column or grade left out keeps its default name. The presets are
`defender`, `sentinel` and `splunk`.

## How it was measured

The data is `GUIDE_Train.csv`: 707,108 graded incidents from 5,340
organisations. The weights were fitted on the earliest 60% in time and tested
on the 282,843 later incidents.

- **Ranking.** Average precision says how high the true positives sit in one
  organisation's queue, where 1 means all of them come first. Its mean over
  the 718 organisations with at least 20 test incidents is 0.72. The inputs
  from linked incidents add 0.06 to it.
- **Close level.** With the default settings, over 525 organisations and
  155,777 test incidents, 34% of incidents were set aside and 3.2% of the true
  positives were among them.

`bench/train.py` fits the weights and prints the ranking numbers.
`bench/close.py` prints the close level numbers. Both read `GUIDE_Train.csv`,
which Microsoft publishes on
[Kaggle](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction).

## Limits

- The numbers above assume that every earlier incident is already graded when
  a new one arrives. They were not measured with grades that arrive late.
- GUIDE is one vendor's data from 2024, about 17 active days per organisation.
  Meerkat has not been measured in a live SOC.
- The `sentinel` and `splunk` presets were written from vendor documentation.
  Neither has read a real export.
- A new organisation has no history. Its first scores come from the shipped
  weights and GUIDE's base rate.
- Meerkat reads files. It has no connector to a SIEM.

## License

MIT. `examples/` is derived from GUIDE under CDLA Permissive 2.0, see `NOTICE`.

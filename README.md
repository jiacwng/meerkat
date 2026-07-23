<p align="center">
  <img
    src="docs/assets/meerkat-analyst.png"
    alt="Pixel-art meerkat security analyst reviewing an alert"
    width="334"
  >
</p>

<h1 align="center">Meerkat</h1>

<p align="center">
  <strong>Alert triage for multi-detector SOC data.</strong>
</p>

## What it does

A SOC gets far more alerts than analysts can read. The detectors have already
fired, so the job left is deciding which alerts to look at first.

Meerkat reads alerts from three detectors, groups them, ranks the groups, and
prints a short daily queue with MITRE ATT&CK context. On the demo environment it
turns 36,358 alerts into 326 groups, and the analyst reads the top 10 per day.

## Key terms

Read these five and the rest of the README makes sense.

- **Alert** — one event from a detector (Suricata, Wazuh or AMiner).
- **Session** — one rule firing on one host, until that host goes quiet for ten
  minutes.
- **Family** — a day's sessions that share the same host, detector and rule.
  This is the group an analyst reviews as one case. "This rule fired 7,068 times
  on this host today" is one decision, not 7,068.
- **Budget** — how many families the analyst reads per day. The demo uses 10.
- **Window** — a labelled time span in the dataset when one attack step happened
  on one host. It is the ground truth. A window is *reached* when a family in the
  queue holds an alert from inside it.

The pipeline is these terms in order:

```
alerts  ->  sessions  ->  families  ->  ranked queue (top budget per day)
```

A Random Forest scores each session, a learned model orders the families, and a
calibrator turns the score into a display percentage. The display percentage
never changes the order; the raw score does.

## Quickstart

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install && git lfs pull      # fetch the demo company's raw alerts
pip install -e .
meerkat demo
```

`meerkat demo` scores the held-out russellmitchell environment and prints the
queue. Without installing, `python -m meerkat demo` does the same.

```
$ meerkat demo
run russellmitchell-...  |  company russellmitchell  |  budget 10  |  326 families
Review queue (top 10 per day)
 handle  date         host           detector  finding                       alerts  score  evid%
 F212    2022-01-24   intranet-...   Suricata  ET SCAN Possible Nmap ...          6   1.00     87
 F218    2022-01-24   intranet-...   Wazuh     Web server 400 error code.     7068   1.00     87
 ...
```

Open a family, drill into a session, read the raw event:

```bash
meerkat inspect F212                          # panels, ATT&CK context, related families
meerkat inspect F218 --distinct http_status   # count values in the family
meerkat inspect F218 --where http_status=403  # keep only matching alerts
meerkat inspect F218 S1 --raw --alerts 1      # the original detector event
meerkat review F212 escalate --note "Nmap user agent, confirmed scan"
meerkat export navigator                      # ATT&CK Navigator layer
```

## Results

Tested leave-one-environment-out: seven companies train the model, the eighth is
held out. A window counts as reached when a queued family holds a labelled alert
from inside it.

| Families read per day | 5 | 10 | 25 |
|---|---:|---:|---:|
| **Windows reached** | **52** | **58** | **58** |

The dataset has 79 labelled windows; 60 of them contain an alert a family could
hold, so 60 is the ceiling. Reading 10 families a day reaches 58 of those 60,
summed over the eight held-out companies (three seeds, 200 trees). Reading more
than 10 adds nothing here, which is why 10 and 25 tie.

Grouping into families is what makes this work. Ranking single alerts instead of
families is beaten by simply sorting on the detector's own severity. Two attack
steps stay out of reach at any budget: a one-off service stop, and network scans
against a host already flagged for other reasons.

The calibrator lowers the Brier score from 0.0301 to 0.0202 and improves all 24
held-out folds. Full method and every negative result are in the report:
**[Meerkat: Ranking Alert Families for Capacity-Limited Triage](docs/report/meerkat.pdf)**.

## Commands

Analyst commands work on a saved run. Support commands set it up.

| Command | What it does |
|---|---|
| `meerkat triage --company C --input DIR --inventory FILE` | score a company into a run and its queue |
| `meerkat queue` | reopen the latest queue (`--all`, `--host`, `--detector`, `--rule`, `--review-state`) |
| `meerkat inspect F003 [S1]` | open a family or session: panels, ATT&CK, related families |
| `meerkat review F003 escalate --note "..."` | record a decision (`escalate`, `benign`, `false-positive`) |
| `meerkat train --holdout C` | fit and save the model |
| `meerkat export navigator` | write an ATT&CK Navigator layer of the run's techniques |
| `meerkat demo` | run the bundled russellmitchell example |

`triage` writes a run once; the other commands reopen it and never score again.
Session views filter with exact matches only: `--where field=value`,
`--exclude field=value`, `--distinct field`, `--alerts N`, `--raw`.

Evidence panels appear in a fixed order (Finding, Identity, Process, Network,
HTTP, DNS, TLS, Provenance) and show only when a field has a value, so the layout
follows what the alert contains, not which detector sent it.

## Platforms

Same commands on Linux, WSL and Windows.

```bash
meerkat demo            # after pip install -e .
python -m meerkat demo  # no install, Windows / WSL / Linux
```

On Windows use Windows Terminal or the VS Code terminal so the tables draw
correctly; Meerkat sets UTF-8 output to avoid garbled characters.

## Dataset

Experiments use [AIT-ADS](https://zenodo.org/records/8263181) (Austrian
Institute of Technology, CC BY 4.0): eight simulated companies watched by
Suricata, Wazuh and AMiner, each hit by a scripted multi-step attack.

One company (russellmitchell) ships with the repo through Git LFS, so the demo
runs right away. The rest is optional:

| Task | Data required |
|---|---|
| The demo | included through Git LFS (`data/raw/russellmitchell_*.json`) |
| Retrain or cross-environment evaluation | `ait_ads.zip` from Zenodo, extracted to `data/raw/` |
| Event label supervision | `alerts_csv.zip` from the [project repo](https://github.com/ait-aecid/alert-data-set), extracted to `data/raw/alerts_csv/` |

Expected layout for the optional downloads:

```
data/raw/<company>_wazuh.json
data/raw/<company>_aminer.json
data/raw/alerts_csv/<company>_alerts.txt
data/raw/inventory/<company>.json
```

Build the local inventories from the official `server_configs` folder:

```bash
python -m pip install PyYAML
python -m core.inventory ../alert-data-set/server_configs data/raw/inventory
```

## Repository layout

```
core/       the pipeline as a library
meerkat/    the analyst command line (one file)
data/       labels, ATT&CK lookup, and the LFS demo alerts
tests/      unittest suite
docs/       the technical report
```

| `core/` module | Purpose |
|---|---|
| `normalize.py` | maps three detector schemas onto one alert table |
| `inventory.py` | loads the company asset inventory |
| `features.py` | turns sessions into numbers |
| `sessions.py` | builds sessions and daily families |
| `classifier.py` | the forest, family re-ranker and calibrator |
| `scenario_eval.py` | held-out evaluation and the trained model bundle |
| `attack_mapping.py` | MITRE ATT&CK technique and tactic mapping |
| `triage_policy.py` | the daily top-K queue |
| `event_labels.py` | official per-alert labels and audit |

## How machines are identified

Grouping only works if two detectors agree on which machine an alert is about.
Meerkat takes an asset inventory as input, before reading any alert, and keeps
three identities apart:

| Field | Meaning |
|---|---|
| `entity_id` | the machine the alert is about |
| `observer_id` | the sensor that produced the alert |
| `entity_in_inventory` | whether that machine belongs to the company |

The inventory decides membership and asset role. Display names come from the
detector, because the official config disagrees with Wazuh's own hostnames on
80,183 alerts.

## Future plans

- **Web interface.** A browser view over the same run and model.
- **More detectors.** The model reads normalized fields, not detector names, so a
  new source needs only a parser and a severity range.
- **GUIDE.** Add the AIT GUIDE anomaly component as a fourth source.
- **Streaming.** Update the queue through the day instead of once per batch.

The report PDF is being updated to the current numbers.

## Status

The pipeline, the CLI and the evaluation are built and tested. The results come
from one testbed with a shared attack script, so they are development evidence,
not a claim about production.

## License

Code under the MIT License. The AIT-ADS dataset is distributed separately by the
Austrian Institute of Technology under CC BY 4.0.

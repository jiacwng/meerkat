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

## Overview

Security operations centres receive far more alerts than analysts can examine.
Detection has already occurred by the time an alert exists, so the outstanding
task is to decide which alerts an analyst examines first.

Meerkat groups the raw alerts, ranks the groups, and produces a bounded daily
review queue annotated with MITRE ATT&CK context. Grouping proceeds in two
stages. A **session** is a single detector rule firing on a single host, closed
once that host has been silent for ten minutes. A **family** collects a day's
sessions that share one host, detector and rule, and is the unit an analyst
adjudicates: a rule that fires 7,068 times on one host in a day becomes a single
case. The analyst reviews a fixed **budget** of families per day, ten in the
demonstration below.

```
alerts  ->  sessions  ->  families  ->  ranked queue (budget per day)
```

A Random Forest scores each session, a learned re-ranker orders the resulting
families, and a calibrator converts the score into a displayed percentage.
Ordering is governed solely by the raw score; the calibrated percentage is shown
to the analyst but never alters it. On the demonstration environment, 36,358
alerts are reduced to 1,487 sessions and 326 families, of which the ten highest
ranked are reviewed each day.

## Quickstart

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install && git lfs pull      # fetch the demo company's raw alerts
pip install -e .
meerkat demo
```

`meerkat demo` scores the held-out russellmitchell environment and prints the
queue. If the package is not installed, `python -m meerkat demo` is equivalent.

```
$ meerkat demo
run russellmitchell-...  |  company russellmitchell  |  budget 10  |  326 families
Review queue (top 10 per day)
 handle  date         host           detector  finding                       alerts  score  evid%
 F212    2022-01-24   intranet-...   Suricata  ET SCAN Possible Nmap ...          6   1.00     87
 F218    2022-01-24   intranet-...   Wazuh     Web server 400 error code.     7068   1.00     87
 ...
```

The commands below open a family, drill into one of its sessions, and read a
single alert down to its raw form:

```bash
meerkat inspect F212                          # panels, ATT&CK context, related families
meerkat inspect F218 --distinct http_status   # count the values in the family
meerkat inspect F218 --where http_status=403  # keep only matching alerts
meerkat inspect F218 S1 --raw --alerts 1      # the original detector event
meerkat review F212 escalate --note "Nmap user agent, confirmed scan"
meerkat export navigator                      # ATT&CK Navigator layer
```

## Results

The AIT dataset labels every step of its scripted attacks with a **window**: a
time interval on a specific host during which that step took place. These windows
are the ground truth. A window is *reached* when a family in the review queue
holds at least one alert that falls inside it.

```
 host intranet-server                     attack window
                                        (web shell upload)
   alerts   .   .    .    .    .   . [ .   .    .    . ] .    .    .
                                      \_______________/
                                      a queued family holds an alert
                                      inside the window   =>  reached
```

Evaluation follows a leave-one-environment-out protocol: seven companies train
the model and the eighth is held out. The score is how many windows the queue
reaches at three daily budgets.

| Families reviewed per day | 5 | 10 | 25 |
|---|---:|---:|---:|
| **Windows reached** | **52** | **58** | **58** |

The dataset contains 79 labelled windows, of which 60 hold an alert that a
family could contain; 60 is therefore the ceiling. At a budget of ten families
per day the queue reaches 58 of those 60, summed across the eight held-out
companies over three seeds with 200 trees. Increasing the budget beyond ten
yields no additional windows, which is why the ten and twenty-five family results
coincide.

The gain derives primarily from the change in unit of review. Ranking individual
alerts is outperformed by sorting on the detectors' native severity. Two attack
steps remain unreachable at any budget: an isolated service stop, and network
scans directed at a host already flagged for other reasons.

The calibrator reduces the Brier score from 0.0301 to 0.0202 and improves all 24
held-out folds. The complete method and every negative result are documented in
the report:
**[Meerkat: Ranking Alert Families for Capacity-Limited Triage](docs/report/meerkat.pdf)**.

## Command-line interface

Analyst commands operate on a saved run; support commands create it.

| Command | Description |
|---|---|
| `meerkat triage --company C --input DIR --inventory FILE` | score a company into a run and its queue |
| `meerkat queue` | reopen the latest queue (`--all`, `--host`, `--detector`, `--rule`, `--review-state`) |
| `meerkat inspect F003 [S1]` | open a family or session: panels, ATT&CK, related families |
| `meerkat review F003 escalate --note "..."` | record a decision (`escalate`, `benign`, `false-positive`) |
| `meerkat train --holdout C` | fit and save the model |
| `meerkat export navigator` | write an ATT&CK Navigator layer of the run's techniques |
| `meerkat demo` | run the bundled russellmitchell example |

The `triage` command writes a run once; the remaining commands reopen it and
perform no further scoring. Session views support exact-match filtering only:
`--where field=value`, `--exclude field=value`, `--distinct field`, `--alerts N`
and `--raw`.

Evidence panels are presented in a fixed order (Finding, Identity, Process,
Network, HTTP, DNS, TLS, Provenance) and appear only when a field is populated,
so the layout is determined by the contents of an alert. Any detector mapped onto
the same normalized fields is displayed identically.

## Platforms

The commands are identical on Linux, WSL and Windows.

```bash
meerkat demo            # after pip install -e .
python -m meerkat demo  # no installation required
```

On Windows, use Windows Terminal or the VS Code terminal so that the tables
render correctly; Meerkat forces UTF-8 output to prevent character corruption.

## Dataset

The experiments use [AIT-ADS](https://zenodo.org/records/8263181) (Austrian
Institute of Technology, CC BY 4.0): eight simulated companies monitored by
Suricata, Wazuh and AMiner, each subjected to a scripted multi-step attack.

One company (russellmitchell) is bundled with the repository through Git LFS, so
the demonstration runs immediately. The remaining data is optional.

| Task | Data required |
|---|---|
| The demonstration | included through Git LFS (`data/raw/russellmitchell_*.json`) |
| Retraining or cross-environment evaluation | `ait_ads.zip` from Zenodo, extracted to `data/raw/` |
| Event-label supervision | `alerts_csv.zip` from the [project repository](https://github.com/ait-aecid/alert-data-set), extracted to `data/raw/alerts_csv/` |

Expected layout for the optional downloads:

```
data/raw/<company>_wazuh.json
data/raw/<company>_aminer.json
data/raw/alerts_csv/<company>_alerts.txt
data/raw/inventory/<company>.json
```

The local inventories are generated from the official `server_configs` folder:

```bash
python -m pip install PyYAML
python -m core.inventory ../alert-data-set/server_configs data/raw/inventory
```

## Repository layout

```
core/       the pipeline as a library
meerkat/    the command-line interface (a single module)
data/       labels, the ATT&CK lookup, and the LFS demo alerts
tests/      the unittest suite
docs/       the technical report
```

| `core/` module | Purpose |
|---|---|
| `normalize.py` | maps three detector schemas onto one alert table |
| `inventory.py` | loads the company asset inventory |
| `features.py` | encodes sessions as numeric features |
| `sessions.py` | builds sessions and daily families |
| `classifier.py` | the forest, family re-ranker and calibrator |
| `scenario_eval.py` | held-out evaluation and the trained model bundle |
| `attack_mapping.py` | MITRE ATT&CK technique and tactic mapping |
| `triage_policy.py` | the daily top-K queue |
| `event_labels.py` | official per-alert labels and audit |

## Host identification

Grouping is only valid if two detectors agree on the machine an alert concerns.
Meerkat requires an asset inventory as input, supplied before any alert is read,
and distinguishes three identities:

| Field | Meaning |
|---|---|
| `entity_id` | the machine the alert concerns |
| `observer_id` | the sensor that produced the alert |
| `entity_in_inventory` | whether that machine belongs to the company |

The inventory determines membership and asset role. Display names are taken from
the detector, because the official configuration disagrees with Wazuh's own
hostnames on 80,183 alerts.

## Future work

- **Web interface.** A browser-based view over the same run and model.
- **Additional detectors.** Because the model operates on normalized fields,
  incorporating a new source requires only a parser and a severity range.
- **GUIDE.** Validation on Microsoft's GUIDE dataset, a large corpus of
  real-world triage decisions.
- **Streaming.** Continuous intra-day updates to the queue, in place of the
  current daily batch.

The report PDF is being updated to the current numbers.

## Status

The pipeline, the command-line interface and the evaluation are implemented and
tested. The results derive from a single testbed with a shared attack script and
should be read as development evidence for this dataset; no claim is made
regarding production performance.

## License

The code is released under the MIT License. The AIT-ADS dataset is distributed
separately by the Austrian Institute of Technology under CC BY 4.0.

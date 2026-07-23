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

## About

Security detectors produce far more alerts than analysts can review. Detection
has already happened by the time an alert exists, so the remaining question is
which alerts a human should read first.

Meerkat reads alerts from Suricata, Wazuh and AMiner, normalizes them against a
company asset inventory, and turns the flood into a fixed size daily review
queue with MITRE ATT&CK context. The pipeline has four steps:

```
alerts  ->  sessions  ->  families  ->  ranked daily queue
```

A **session** is one detector rule firing on one asset until that stream goes
quiet for ten minutes. A **family** collects a day's sessions that share the
same asset, detector and rule. The family is the unit an analyst actually
adjudicates: deciding about "this rule fired 7,068 times on this host today" is
one judgement, not 7,068 of them. On the demo environment this turns 36,358
alerts into 1,487 sessions and 326 families, of which the analyst reviews the
top 10 per day.

A Random Forest scores each session, a learned re-ranker orders the families,
and a calibrator attaches a display probability. Methods and full experiments
are in the technical report:
**[Meerkat: Ranking Alert Families for Capacity-Limited Triage](docs/report/meerkat.pdf)**.

## Quickstart

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install && git lfs pull      # fetch the demo company's raw alerts
pip install -e .
meerkat demo
```

`meerkat demo` scores the held-out russellmitchell environment with the shipped
model and prints the ranked queue. If you have not installed the package,
`python -m meerkat demo` does the same thing.

```
$ meerkat demo
run russellmitchell-...  |  company russellmitchell  |  budget 10  |  326 families
Review queue (top 10 per day)
 handle  date         host           detector  finding                          alerts  score  evid%
 F001    2022-01-21   inet-firewall  AMiner    AMiner: Unusual occurrence ...         6   1.00     87
 ...
 F212    2022-01-24   intranet-...   Suricata  ET SCAN Possible Nmap User-...        6   1.00     87
 F218    2022-01-24   intranet-...   Wazuh     Web server 400 error code.         7068   1.00     87
```

Open one family, drill into a session, read the raw source event:

```bash
meerkat inspect F212                       # panels, ATT&CK context, related families
meerkat inspect F218 --distinct http_status
meerkat inspect F218 --where http_status=403 --alerts 5
meerkat inspect F218 S1 --raw --alerts 1   # the original detector event
meerkat review F212 escalate --note "Nmap user agent, confirmed scan"
meerkat export navigator                   # ATT&CK Navigator layer of observed techniques
```

## Results

Evaluated by leave-one-environment-out testing across eight simulated
companies: seven train the model, the eighth is held out, and calibration stays
inside the training seven. A window counts as reached when a queued family holds
a labelled alert inside that window.

| Reviews per day | 5 | 10 | 25 |
|---|---:|---:|---:|
| **Windows reached (learned re-ranker)** | **52** | **58** | **58** |

Out of 60 reachable attack windows, summed across the eight held-out companies
(three seeds, 200 trees). Precision at these budgets sits on the measured data
ceiling, so the queue is close to the best any ranker could do at this workload,
not merely better than a baseline.

Calibration lowers the pooled Brier score from 0.0301 to 0.0202 and improves
every one of the 24 held-out folds. The displayed probability never changes the
queue order; the raw ranking score decides the analyst's day.

The change of unit does most of the work. Ranking individual alerts, rather than
families, is beaten by sorting on native detector severity. Two attack phases
stay hard to reach at any budget, single-window service stops and network scans
against a host already under investigation for other reasons; the report keeps
every negative result unchanged.

## CLI reference

Analyst commands work a saved run. Support commands set it up.

| Command | Role | What it does |
|---|---|---|
| `meerkat triage --company C --input DIR --inventory FILE` | analyst | score a company into a run directory and the queue |
| `meerkat queue` | analyst | reopen the latest run's queue (`--all`, `--host`, `--detector`, `--rule`, `--review-state`) |
| `meerkat inspect F003 [S1]` | analyst | open a family or session: panels, ATT&CK, related families |
| `meerkat review F003 escalate --note "..."` | analyst | record a decision (`escalate`, `benign`, `false-positive`) |
| `meerkat train --holdout C` | support | fit and save the model |
| `meerkat export navigator` | support | write an ATT&CK Navigator layer of the run's techniques |
| `meerkat demo` | support | run the bundled russellmitchell example end to end |

A run is written once by `triage` and reopened by the rest without scoring
again. `--run ID` selects an older run; the default is the latest successful
one. Session views filter with exact operations only (`--where field=value`,
`--exclude field=value`, `--distinct field`, `--alerts N`, `--raw`), validated
against the normalized schema.

Evidence panels follow one fixed order (Finding, Identity, Process, Network,
HTTP, DNS, TLS, Provenance) and appear only when a normalized field carries a
value, so the layout depends on what the alert contains rather than which
detector produced it.

## Platforms

The CLI runs the same on Linux, WSL and Windows.

```bash
# Linux / WSL / macOS
meerkat demo

# Windows PowerShell, no install needed
python -m meerkat demo
```

On Windows, use Windows Terminal or the VS Code terminal so the box-drawing
renders; Meerkat forces UTF-8 output so the tables do not garble on a legacy
code page. `pip install -e .` also creates a `meerkat` command on Windows.

## Dataset

Experiments use [AIT-ADS](https://zenodo.org/records/8263181) (Austrian
Institute of Technology, CC BY 4.0): eight simulated enterprise environments
monitored by Suricata, Wazuh and AMiner, each subjected to a scripted multi step
attack.

One environment (russellmitchell) ships with the repository through Git LFS, so
the demo runs immediately. The rest is optional and only needed to retrain or to
reproduce the cross-environment evaluation:

| Task | Data required |
|---|---|
| The bundled demo | included through Git LFS (`data/raw/russellmitchell_*.json`) |
| Retrain or cross-environment evaluation | `ait_ads.zip` from Zenodo, extracted to `data/raw/` |
| Event label supervision and audit | `alerts_csv.zip` from the [project repository](https://github.com/ait-aecid/alert-data-set), extracted to `data/raw/alerts_csv/` |

Expected layout for the optional downloads:

```
data/raw/<scenario>_wazuh.json
data/raw/<scenario>_aminer.json
data/raw/alerts_csv/<scenario>_alerts.txt
data/raw/inventory/<scenario>.json
```

Generate the local AIT inventories from the official `server_configs` folder:

```bash
python -m pip install PyYAML
python -m core.inventory ../alert-data-set/server_configs data/raw/inventory
```

## Repository layout

```
core/       the pipeline as a library (detector-agnostic once alerts are normalized)
meerkat/    the analyst command line over that library
data/       labels, ATT&CK lookup, detection mappings, and the LFS demo alerts
tests/      unittest suite
docs/       the technical report
```

| `core/` module | Purpose |
|---|---|
| `normalize.py` | maps three detector schemas onto one alert table |
| `inventory.py` | loads the company asset inventory |
| `features.py` | encodes sessions as numeric features |
| `sessions.py` | builds sessions and daily families |
| `classifier.py` | the forest, family re-ranker and calibrator |
| `scenario_eval.py` | leave-one-scenario-out evaluation and the trained bundle |
| `attack_mapping.py` | MITRE ATT&CK technique and tactic mapping |
| `triage_policy.py` | the daily top-K queue |
| `event_labels.py` | official per alert label loading and audit |

## How machines are identified

Alert grouping only works if two detectors agree on which machine they are
describing. Meerkat takes an asset inventory as an input, supplied before any
alert is read, and separates three identities:

| Field | Meaning |
|---|---|
| `entity_id` | the machine the alert is about, always an address the detector reported |
| `observer_id` | the sensor or collector that produced the alert |
| `entity_in_inventory` | whether that machine belongs to the company |

The inventory is used for membership and asset role. Display names come from the
detector, because the official AIT configuration disagrees with Wazuh's own
hostnames on 80,183 alerts, all of them permutations of external mail server
names within one environment.

## Future plans

- **Web interface.** A browser view over the same run directory and model, so
  the queue, drill-down and review capture the CLI already produces get a
  point-and-click front end.
- **More detectors.** The model works on normalized fields, not detector names,
  so a new source needs only a parser and a severity range. A written adapter
  contract and per-detector severity config will turn that into a small config
  change rather than a code change.
- **GUIDE integration.** Fold the AIT GUIDE anomaly component into the same
  normalized table as a fourth source.
- **Streaming.** Carry session state across fetches so the queue updates through
  the day instead of running as one daily batch.

The report PDF is being brought up to date on the final numbers alongside this
work.

## Status

The pipeline, the CLI and the cross-environment evaluation are built and tested.
Results come from eight simulated environments generated by one testbed with a
shared attack script, so they are development evidence rather than a claim about
production performance.

## License

Code released under the MIT License. The AIT-ADS dataset is distributed
separately by the Austrian Institute of Technology under CC BY 4.0.

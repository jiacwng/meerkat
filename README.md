<p align="center">
  <img
    src="docs/assets/meerkat-analyst.png"
    alt="Pixel-art meerkat security analyst reviewing an alert"
    width="334"
  >
</p>

<h1 align="center">Meerkat</h1>

<p align="center">
  <strong>ML-assisted alert triage for multi-detector SOC data.</strong>
</p>

## What I built

I built Meerkat to explore a practical SOC question: when several detectors
produce more alerts than an analyst can review, which ones should appear first?

Meerkat reads alerts from Wazuh, Suricata and AMiner, normalizes their different
formats, groups repeated activity and ranks the resulting cases. The output is a
small daily review queue with the original evidence and MITRE ATT&CK context
still attached.

The main idea is to rank **families**, not isolated alerts. For example, one
Wazuh rule firing 7,068 times on the same host during one day becomes one family
to investigate, rather than 7,068 separate decisions.

```text
detector alerts
      |
      v
normalized alerts -> sessions -> families -> ranked daily queue
```

- A **session** contains one detector rule firing on one host until that stream
  stays quiet for more than ten minutes.
- A **family** joins same-day sessions with the same host, detector and rule.
- A **budget** is the number of families the analyst can review per day.

On the bundled example, Meerkat reduces 36,358 alerts to 1,487 sessions and 326
families. With a budget of 10, it presents the top 10 families for each of the
four days in the scenario.

## How it works

Meerkat uses two small ML layers:

1. A Random Forest scores each session from its volume, duration, detector,
   standardized severity, rule rarity, ATT&CK presence and asset context.
2. A logistic re-ranker combines the child-session scores and family-level
   context to order the final queue.

A separate calibrator turns the family score into an evidence percentage for
display. That percentage does not control the queue order and should not be read
as an analyst verdict.

Raw host names, IP addresses, rule IDs and alert names are not model features.
This prevents the model from simply memorizing one of the training companies.
An inventory is still used outside the model to identify the affected machine,
distinguish it from the observing sensor and attach asset roles.

## Quick start

Meerkat requires Python 3.11 or newer and Git LFS for the demo alerts.

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install
git lfs pull
python -m pip install -e .
meerkat demo
```

The demo uses a model trained on seven AIT-ADS environments and ranks
`russellmitchell` as the unseen eighth environment.

```text
run russellmitchell-... | company russellmitchell | budget 10 | 326 families

handle  date        host           detector  finding                         alerts
F001    2022-01-21  inet-firewall  AMiner    Unusual DNS query frequencies        6
F002    2022-01-21  inet-firewall  AMiner    New service_start combination        1
F003    2022-01-21  inet-firewall  AMiner    New service_stop combination         1
```

The queue is saved as a run, so investigation commands do not score the data
again:

```bash
meerkat queue
meerkat inspect F003
meerkat inspect F003 S1
meerkat review F003 escalate --note "Unexpected service change"
meerkat export navigator
```

## Analyst workflow

| Command | Purpose |
|---|---|
| `meerkat triage --company C --input DIR --inventory FILE` | normalize and score one company's alert batch |
| `meerkat queue` | reopen the latest queue or filter all scored families |
| `meerkat inspect F003 [S1]` | inspect a family, one session or its original alerts |
| `meerkat review F003 escalate --note "..."` | record an escalation, benign finding or false positive |
| `meerkat export navigator` | export observed techniques as an ATT&CK Navigator layer |
| `meerkat train --holdout C` | train and save a reusable model bundle |
| `meerkat demo` | run the bundled held-out-company example |

Useful queue filters include:

```bash
meerkat queue --all
meerkat queue --host intranet-server
meerkat queue --detector wazuh
meerkat queue --review-state escalate
```

Inspection starts with a summary rather than a raw alert dump. Evidence is
shown in consistent sections such as finding, identity, process, network, HTTP,
DNS, TLS and provenance. Empty sections are hidden.

```bash
meerkat inspect F218 --distinct http_status
meerkat inspect F218 --where http_status=403
meerkat inspect F218 --exclude http_status=404 --alerts 20
meerkat inspect F218 S1 --raw --alerts 1
```

Reviews are appended to `reviews.jsonl` inside the run directory. The most
recent entry is the current decision, while earlier entries remain available as
a small audit trail.

## Evaluation

The evaluation uses all eight AIT-ADS environments. For each fold, seven
environments train the models and the eighth remains unseen. The training
vocabulary, model features, re-ranker and calibrator are all fitted without the
held-out environment.

AIT-ADS describes its scripted attack steps with labelled time windows. Meerkat
counts a window as **strictly reached** only when the daily queue contains an
officially event-labelled alert from that window.

| Families reviewed per day | 5 | 10 | 25 |
|---|---:|---:|---:|
| Max child-session score | 44 | 53 | 58 |
| **Learned family re-ranker** | **52** | **58** | **58** |

These values are totals across the eight held-out environments, averaged over
three random seeds with 200 trees.

The dataset contains 79 attack windows. Only 60 contain at least one official
event-labelled alert, so strict coverage cannot exceed 60 with this supervision.
At a budget of 10 families per day, the re-ranker reaches 58 of those 60
label-reachable windows.

Calibration reduces the pooled Brier score from 0.0301 to 0.0202 and improves
all 24 held-out environment and seed combinations. It improves how the displayed
percentage matches observed outcomes; it does not change the ranking.

The full experimental method, including rejected feature bundles and negative
results, is documented in
**[Meerkat: Ranking Alert Families for Capacity-Limited Triage](docs/report/meerkat.pdf)**.

## Dataset

Meerkat uses the
[AIT Alert Data Set](https://zenodo.org/records/8263181), built from eight
simulated company environments monitored by Wazuh, Suricata and AMiner. The
companion [AIT-ADS repository](https://github.com/ait-aecid/alert-data-set)
provides the detector configuration, asset configuration and per-alert labels.

The demo needs only the bundled `russellmitchell` raw files and pretrained
model. Reproducing the full cross-environment evaluation requires all eight
scenarios and the event-label files.

```text
data/raw/<company>_wazuh.json
data/raw/<company>_aminer.json
data/raw/alerts_csv/<company>_alerts.txt
data/raw/inventory/<company>.json
```

Inventories can be generated from the official `server_configs` directory:

```bash
python -m pip install PyYAML
python -m core.inventory ../alert-data-set/server_configs data/raw/inventory
```

## Project structure

```text
core/
  normalize.py       detector parsing and the shared alert schema
  inventory.py       entity and asset-role resolution
  sessions.py        session and family construction
  features.py        leakage-safe session features
  classifier.py      Random Forest, family re-ranker and calibration
  scenario_eval.py   leave-one-environment-out evaluation and model bundles
  attack_mapping.py  MITRE ATT&CK enrichment
  triage_policy.py   bounded daily queue

meerkat/
  cli.py             training, triage, inspection and review commands

models/               pretrained demo bundle
docs/                 report and project assets
```

## Scope and limitations

Meerkat is a student research project, not a replacement for a SIEM or case
management platform.

- The results come from one simulated testbed whose environments share an attack
  script. They do not establish production performance.
- Triage is currently batch-based rather than streaming.
- Review state is local and single-user. There is no authentication, ownership
  assignment or multi-analyst locking.
- The current adapters cover Wazuh, Suricata and AMiner. A new detector still
  needs a parser that maps its fields and severity scale into Meerkat's schema.
- ATT&CK mappings provide investigation context. They do not prove that several
  observations belong to one attack campaign.

The next product step is a browser interface over the same saved runs. The
ranking and evaluation code remain independent of that interface.

## License

Meerkat is released under the MIT License. AIT-ADS is distributed separately by
the Austrian Institute of Technology under CC BY 4.0.

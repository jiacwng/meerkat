<p align="center">
  <img
    src="docs/assets/meerkat-analyst.png"
    alt="Pixel-art meerkat security analyst reviewing an alert"
    width="334"
  >
</p>

<h1 align="center">meerkat</h1>

<p align="center">
  <strong>ML-assisted alert triage for multi-detector SOC data.</strong>
</p>

<p align="center">
  <a href="https://github.com/jiacwng/meerkat/actions/workflows/ci.yml">
    <img src="https://github.com/jiacwng/meerkat/actions/workflows/ci.yml/badge.svg" alt="CI status">
  </a>
  <img src="https://img.shields.io/badge/tests-284%20passing-brightgreen" alt="284 tests passing">
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue" alt="Python 3.11 to 3.13">
  <img src="https://img.shields.io/badge/license-MIT-informational" alt="MIT license">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a>
  &nbsp;&middot;&nbsp;
  <a href="#walkthrough">Walkthrough</a>
  &nbsp;&middot;&nbsp;
  <a href="#results">Results</a>
  &nbsp;&middot;&nbsp;
  <a href="docs/report/meerkat.pdf">Technical report</a>
</p>

## Overview

Wazuh, Suricata and a log anomaly detector each raise alerts on their own
severity scale, tens of thousands a day on a mid-sized network. None of them
ranks the others, so whoever looks first has to choose what to open.

> **Out of everything raised today, which alerts are the important ones?**

Ranking answers that by scoring alerts and sorting them. Meerkat adds one
assumption, and it is an assumption rather than a finding: the list is worked
until the reviewing time runs out, not to the end. How much time that is varies
by team, so it stays a number you set.

That changes the measure to **coverage at a budget**: for a given number of cases
opened, how much of the attack does the queue point at? Not every alert of it,
since one item is enough to start pulling the thread. What counts is whether
something in the queue leads to each part of the attack, since a part the queue
misses entirely goes unnoticed.

Ranking alerts fills that budget badly, since one step of an intrusion can raise
thousands of near-identical alerts while a privilege escalation raises three.
Commercial platforms avoid this by grouping alerts into incidents upstream, and
most published work starts from those incidents. An open-source stack has no such
layer, which leaves the question the [report](docs/report/meerkat.pdf) is about.

> **What should one item in the queue be, so that limited review reaches as
> much of the attack as possible?**

Meerkat reads **Wazuh** (runs on each machine, watches logs and processes),
**Suricata** (watches network traffic) and **AMiner** (flags unusual log lines).
The first two are enough to run; the third improves coverage.

### How alerts are grouped

Alerts are grouped twice before anything is ranked.

<p align="center">
  <img
    src="docs/assets/pipeline.svg"
    alt="36,358 alerts group into 3,169 sessions, collapse into 1,771 daily families, and are cut to the 40 reviewed at a budget of 10 a day, which is a setting"
    width="100%"
  >
</p>

A **session** is one rule firing on one machine until that stream is quiet for ten
minutes. A **family** joins the same day's sessions that share a machine, a
detector and a rule, so one rule firing 7,068 times becomes one item to judge. A
**budget** is how many families you review per day.

### The pipeline

Four stages run between the raw files and the queue.

**Normalise.** The three detectors write different formats, name the same machine
in different ways and score severity on scales that do not compare. This stage
produces one table: a shared severity scale, and every alert attached to an asset
from your inventory.

**Group.** Alerts become sessions, sessions become daily families, as above.

**Score sessions.** A random forest gives each session a probability. It is
trained *positive-unlabelled*: a SOC can say an incident ran on this host between
these times, but not which alerts inside that window were the attack. Nothing
inside a window is therefore asserted positive. Sessions in a reported incident
share the weight of one label; sessions outside every incident are negatives.

**Rank families.** A logistic regression scores each family from its sessions'
scores, the shape of the family and the role of the machine it landed on. The
highest scores become the day's queue. A second logistic regression (Platt
scaling) turns the score into the percentage shown in the `conf` column; it is
for reading only and never changes the order.

## Quick start

Python 3.11 or newer, and Git LFS for the bundled example alerts.

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install && git lfs pull
python -m pip install -e .
meerkat demo
```

The clone contains a trained model and one company's alerts, so this runs with no
further download.

<p align="center">
  <img
    src="docs/assets/queue.svg"
    alt="Review queue for one day of the demo, listing ten ranked families with host, detector, finding, alert count and score"
    width="100%"
  >
</p>

`score` sets the order. `conf%` is the same score read as a probability: among
families scoring this high in training, about 87% were real. A low value means
*probably not worth opening*, not *unsure*. It never changes the order.

## Commands

```
  meerkat demo                      score the bundled example alerts

  meerkat inventory                 create a starter inventory from your alerts
  meerkat check                     report what triage will see, before running it
  meerkat triage --input DIR        score one batch into a run
  meerkat queue                     the ranked queue for a saved run
  meerkat inspect F003 [S1]         open one family, one session, or raw alerts
  meerkat review F003 benign        record a decision
  meerkat retrain --incidents FILE  refit the model on your own incident records
  meerkat drift                     how far your alerts have moved from training
  meerkat export queue              the queue as csv or json
  meerkat export navigator          ATT&CK layer of one run, all its alerts
  meerkat runs                      list saved runs

  exit codes   0 success   1 error   2 bad arguments
               3 retrain refused     4 major drift
```

Every command takes `--help`. `queue` filters with `--day`, `--host`, `--detector`
and `--all`, recuts with `--budget`, and emits `--json`.

## Walkthrough

Put your alert exports in a directory named `alerts`. Their filenames do not
matter; each `.json` file is read a few lines deep and recognised by its
contents. Every command below takes `--input` if you keep them somewhere else.

The output shown in each step is a capture of this walkthrough being run against
a directory of Wazuh, Suricata and AMiner exports.

### 1. Describe your machines

```bash
meerkat inventory
```

<p align="center">
  <img
    src="docs/assets/inventory.svg"
    alt="inventory output: ten assets written from 41488 alert lines, a warning that roles are empty, and the list of role names to choose from"
    width="100%"
  >
</p>

One asset per machine, with `roles` left blank for you to fill in:

```json
{
  "company": "alerts",
  "assets": [
    {
      "hostname": "10.143.0.103",
      "ip_addresses": ["10.143.0.103"],
      "roles": []
    },
    {
      "hostname": "mail",
      "ip_addresses": ["172.19.130.4"],
      "roles": []
    }
  ]
}
```

A machine keeps its own hostname where the alerts report one, and is labelled by
its address otherwise.

Filling in the roles is the one manual step, and it matters: the model reads
asset role as a feature, so assets left blank are scored without it.
`meerkat inventory --list-roles` prints the vocabulary.

```json
    {
      "hostname": "mail",
      "ip_addresses": ["172.19.130.4"],
      "roles": ["mail_server", "internet_facing"]
    }
```

### 2. Check what the tool sees

```bash
meerkat check
```

<p align="center">
  <img
    src="docs/assets/check.svg"
    alt="check output: a per-detector table of alert counts, hosts, inventory match rate and distinct rules, the period covered, and a warning that 15% of alerts are on hosts outside the inventory"
    width="100%"
  >
</p>

It exits non-zero and says what is wrong if machines are missing from the
inventory, roles are blank, or the alerts do not parse.

### 3. Score a batch

```bash
meerkat triage --budget 10
```

Scores the batch once and saves a run under `runs/`. Every command after it
reopens that run instead of scoring again.

### 4. Work the queue

```bash
meerkat queue --day 2022-01-21
meerkat inspect F003
meerkat review F003 escalate --session S1 --note "Unexpected service change"
```

`inspect` opens one family: its ranking signals, the evidence pulled from the
original alerts, related activity on the same machine, and the MITRE ATT&CK
tactics observed there.

<p align="center">
  <img
    src="docs/assets/inspect.svg"
    alt="Inspect view of one family showing its summary, ranking signals and evidence panels"
    width="100%"
  >
</p>

### 5. Train it on your own history

```bash
meerkat retrain --incidents tickets.csv
```

`tickets.csv` is a `start,end,host,verdict` export from your ticketing system: an
incident ran on this machine between these times, and this was the outcome.

Meerkat trains on the earlier days, scores itself on the most recent ones, and
refuses to save the new model unless most of its attempts beat the current one on
those held-out days.

### 6. Watch for change

```bash
meerkat drift
```

<p align="center">
  <img
    src="docs/assets/drift.svg"
    alt="drift output: alert, session and family counts against the training set, then a table of features ranked by population stability index with a verdict, the training median and the current value"
    width="100%"
  >
</p>

This needs no incident records. It reports whether the incoming alerts have
changed shape since the model was trained, for example new rules or machines
missing from the inventory. It does not report whether the ranking has become less
accurate, which cannot be established without labelled outcomes.

PSI, the population stability index, compares one feature's distribution now
against the same feature at training time. Below 0.10 counts as stable, above
0.25 as a major shift.

## MITRE ATT&CK

Alerts are mapped to ATT&CK techniques from the detector's own rule metadata where
it exists, and from a keyword table otherwise. `inspect` shows the tactics seen on
a machine in the order they occurred, which is often what makes a family worth
escalating.

```bash
meerkat export navigator
```

writes a layer file that opens in the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) under
**Open Existing Layer**.

It covers **one run**: the latest by default, or `--run ID` for an older one, and
`meerkat runs` lists them. Within that run it covers every alert, including
alerts whose family never entered the queue; `--queue-only` narrows it to what
was actually reviewed. The layer is written inside the run's own directory, so
each triage keeps its own. Runs are not combined into a single layer.

<p align="center">
  <img
    src="docs/assets/attack-coverage.svg"
    alt="ATT&CK Navigator layer showing the techniques observed in the demo environment"
    width="100%"
  >
</p>

Mapped tactics are reported independently and are not a claim that they form one
campaign.

## Results

Measured on the [AIT Alert Data Set](https://zenodo.org/records/8263181): eight
simulated company networks in which a scripted attack was run and every alert it
produced was labelled. The model trains on seven networks and is scored on the
eighth, so the network being scored is never one it trained on.

| Ranking method | 5 | 10 | 25 |
|---|---:|---:|---:|
| **Meerkat** | **51** | **58** | **58** |
| Best single session in the family | 44 | 54 | 58 |
| Family size (alert count) | 29 | 30 | 39 |
| Detectors' own severity | 19 | 33 | 46 |
| Random order | 21 | 31 | 45 |

Attack steps reached, at budgets of 5, 10 and 25 families a day. 60 of the 79
scripted steps are findable at all; the rest produce no labelled alert from any
detector. Without AMiner, 41 are findable and Meerkat still reaches all 41.

The [technical report](docs/report/meerkat.pdf) covers the method, the designs
that were dropped, and the limits of the evaluation.

## Limitations

- The results come from one simulated testbed whose networks share an attack
  script. They do not establish how the tool performs in production.
- An attack that trips the same rule as the surrounding noise, at the same
  severity and mixed in time with it, leaves nothing to separate.
- Ranking is by likelihood, not by business risk. A critical server and a spare
  workstation showing identical activity score the same.
- Triage runs in batches, not continuously. Review decisions are stored locally
  for a single user.
- Wazuh, Suricata and AMiner are supported. Another detector needs an adapter.
- Retraining is only as good as the incident records a company can supply.

## Model files

Models are [skops](https://skops.readthedocs.io/) files: loading one rebuilds only
the types allowlisted in `core/classifier.py`, so it cannot run arbitrary code the
way a pickle can. The JSON beside it records the scikit-learn version, training
data and a checksum, which catches corruption but is not a signature. Run
directories under `runs/` are plain pickles, so open only your own.

## Reproducing the results

The results table is produced by `bench/`, which is in the repository but not in
the installed package. It needs the AIT Alert Data Set itself, Zenodo record
[8263181](https://zenodo.org/records/8263181), a 2.7 GB download that no clone
carries. [bench/README.md](bench/README.md) gives the file layout and the commands.

## Development

```bash
python -m unittest discover -s tests -p "test_*.py"
ruff check core meerkat bench tests
```

## License

MIT. The AIT Alert Data Set is distributed separately by the Austrian Institute of
Technology under CC BY 4.0.

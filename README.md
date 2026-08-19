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
  <img src="https://img.shields.io/badge/tests-452%20passing-brightgreen" alt="452 tests passing">
  <img src="https://img.shields.io/badge/coverage-75%25-brightgreen" alt="75% coverage">
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue" alt="Python 3.11 to 3.13">
  <img src="https://img.shields.io/badge/license-MIT-informational" alt="MIT license">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a>
  &nbsp;&middot;&nbsp;
  <a href="docs/manual.md">Manual</a>
  &nbsp;&middot;&nbsp;
  <a href="#results">Results</a>
</p>

## Overview

Wazuh, Suricata and a log anomaly detector each raise their own alerts, tens
of thousands a day, on severity scales that do not compare, and none ranks
the others. Meerkat scores the day's alerts and builds a review queue sized
to the time a team has.

Commercial stacks group alerts into incidents before ranking them (Microsoft
Sentinel, AIP's GraphWeaver). An open-source detector stack has no such layer,
which leaves the question:

> **What should one item in the review queue be, so that limited review
> reaches as much of the attack as possible?**

Meerkat groups before ranking: a **session** is one rule firing on one machine
until it falls quiet for ten minutes, and a **family** joins the same day's
sessions sharing a machine, a detector and a rule. A random forest scores each
session, a logistic regression ranks each family, and the day's top families
are the queue. The budget is yours to set.

<p align="center">
  <img
    src="docs/assets/pipeline.svg"
    alt="36,358 alerts group into 1,487 sessions, collapse into 326 daily families, and are cut to the 40 reviewed at a budget of 10 a day, which is a setting"
    width="100%"
  >
</p>

## Quick start

Python 3.11 or newer, and Git LFS for the bundled example alerts.

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install && git lfs pull
python -m pip install -e .
meerkat demo
```

The clone contains a trained model and one company's alerts, so this runs with
no further download. Those alerts are part of the AIT Alert Data Set, under CC
BY 4.0; [NOTICE](NOTICE) records what is included. The first day's queue,
recorded:

```text
run russellmitchell-20260724-230029  |  company russellmitchell  |  budget 10  |  326 families
Review queue (top 10 per day, 2022-01-21)  |  F1 = top priority
┏━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━━━┳━━━━━━━━┓
┃ handle ┃ date       ┃ start ┃ host          ┃ detector ┃ finding                                  ┃ alerts ┃ score ┃    esc% ┃ review ┃
┡━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━━━╇━━━━━━━━┩
│ F1     │ 2022-01-21 │ 06:33 │ inet-firewall │ AMiner   │ AMiner: Unusual occurrence frequencies o │      6 │  1.00 │         │        │
│ F2     │ 2022-01-21 │ 11:27 │ inet-firewall │ AMiner   │ AMiner: New service_start parameter comb │      1 │  0.98 │         │        │
│ F3     │ 2022-01-21 │ 11:27 │ inet-firewall │ AMiner   │ AMiner: New service_stop parameter combi │      1 │  0.98 │         │        │
│ F4     │ 2022-01-21 │ 00:00 │ inet-firewall │ AMiner   │ AMiner: New ip address in DNS logs.      │     16 │  0.72 │         │        │
│ F5     │ 2022-01-21 │ 16:10 │ inet-firewall │ Suricata │ SURICATA HTTP gzip decompression failed  │      1 │  0.29 │         │        │
│ F6     │ 2022-01-21 │ 00:02 │ inet-firewall │ AMiner   │ AMiner: New event type.                  │      2 │  0.24 │         │        │
│ F7     │ 2022-01-21 │ 06:37 │ webserver     │ Suricata │ SURICATA TLS invalid record/traffic      │    105 │  0.19 │         │        │
│ F8     │ 2022-01-21 │ 05:24 │ inet-firewall │ Suricata │ SURICATA TLS invalid record/traffic      │    674 │  0.17 │         │        │
│ F9     │ 2022-01-21 │ 05:24 │ inet-firewall │ Suricata │ SURICATA TLS invalid handshake message   │    674 │  0.17 │         │        │
│ F10    │ 2022-01-21 │ 06:37 │ webserver     │ Suricata │ SURICATA TLS invalid handshake message   │    105 │  0.17 │         │        │
└────────┴────────────┴───────┴───────────────┴──────────┴──────────────────────────────────────────┴────────┴───────┴─────────┴────────┘
```

`score` alone sets the order. `esc%` fills in as you review: how often you escalated your past reviewed families at the same score. A fresh environment shows the score alone.

## Using it

```bash
meerkat inventory        # asset inventory from your alerts, once
meerkat check            # what triage will see
meerkat triage           # score a batch into a run
meerkat browse           # work the queue, record decisions
meerkat export decisions # the review pass as a grid
meerkat retrain --incidents tickets.csv  # refit on your own history
```

`inspect` opens any family, session or alert with its evidence and ATT&CK
techniques; `export navigator` writes an ATT&CK Navigator layer. Retraining
needs an incident CSV, the alert archive it covers, and the inventory, and it
saves a new model only when it beats the shipped one on your own held-out
incidents. The [manual](docs/manual.md) covers every command, flag and input
format.

## Results

Measured on the [AIT Alert Data Set](https://zenodo.org/records/8263181): eight
simulated company networks in which a scripted attack was run and every alert it
produced was labelled. The model trains on seven networks and is scored on the
eighth.

Before any ranking, the grouping does most of the reduction: an average
company-day of 56,899 alerts becomes 78 review items, and the item count stays
between 59 and 86 while daily volume ranges from 9,012 to 109,497.

One queue item is a family: every alert of one rule, on one machine, over one
day. The key keeps the item uniform, so one judgement usually settles it, and
the sessions inside are there to open when it does not. The day's workload is
ten of these summaries. The alert column below is what sits underneath them,
opened on demand while investigating.

| Ranking method | steps reached (of 60) | items opened per day | alerts behind them, per day |
|---|---:|---:|---:|
| **Meerkat** | **58** | **10** | **5,775** |
| Detectors' own severity | 33 | 10 | 4,542 |

A step is one phase of the scripted attack on one machine, reached when the
queue holds an alert labelled to it. 60 of the 79 steps are findable at all.
At ten items a day, Meerkat reaches 58; the detectors' own severity ordering
reaches 33, at a similar reading cost. Full tables and every baseline:
[bench/README.md](bench/README.md).

The [technical report](docs/report/meerkat.pdf) covers the method and the
limits of the evaluation.

## Limitations

- The headline results come from one simulated testbed whose networks share an attack script; a second testbed (CAM-LDS) cross-checks the transfer of the ranking weights only. Neither establishes how the tool performs in production.
- An attack that trips the same rule as the surrounding noise, at the same
  severity and mixed in time with it, leaves nothing to separate.
- Ranking is by likelihood alone and carries no notion of business
  criticality. A critical server and a spare workstation showing identical
  activity score the same.
- Triage runs in batches, one complete day at a time. A real SOC works in
  shifts on a live stream, and meerkat does not fit that schedule.
- Wazuh, Suricata and AMiner are supported. Another detector needs an adapter.
- Retraining is only as good as the incident records a company can supply, and
  the shipped ranking weights stay unless `--refit-ranking-weights` beats them
  on your own held-out incidents.
- Below roughly 300 training sessions, drift reporting is mostly noise.

## Reference

- [Manual](docs/manual.md) — install, inputs, commands, the model
- [Benchmark](bench/README.md) — reproduce the results table

Cite the AIT Alert Data Set if you publish these numbers; `CITATION.cff` has
the entries. MIT licensed, see [LICENSE](LICENSE); [NOTICE](NOTICE) carries
the AIT and MITRE ATT&CK attributions.

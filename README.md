<p align="center">
  <img
    src="docs/assets/meerkat-analyst.png"
    alt="Pixel-art meerkat security analyst reviewing an alert"
    width="334"
  >
</p>

<h1 align="center">meerkat</h1>

<p align="center">
  <strong>End-of-day alert triage for Wazuh.</strong>
</p>

<p align="center">
  <a href="https://github.com/jiacwng/meerkat/actions/workflows/ci.yml">
    <img src="https://github.com/jiacwng/meerkat/actions/workflows/ci.yml/badge.svg" alt="CI status">
  </a>
  <img src="https://img.shields.io/badge/python-3.12%20%7C%203.13-blue" alt="Python 3.12 and 3.13">
  <img src="https://img.shields.io/badge/license-MIT-informational" alt="MIT license">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a>
  &nbsp;&middot;&nbsp;
  <a href="docs/manual.md">Manual</a>
  &nbsp;&middot;&nbsp;
  <a href="#results">Results</a>
</p>

Meerkat is a command-line tool that turns one day of Wazuh alerts into a short
review queue for the next morning. It groups alerts that belong together,
scores each group, and lists the top ten for an analyst to work through in the
terminal. It reads Wazuh, including the Suricata alerts in the Wazuh feed, and
optionally AMiner log anomalies.

## Quick start

Python 3.12 or newer, and Git LFS for the bundled example alerts.

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install && git lfs pull
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e .
meerkat demo
```

`meerkat demo` scores one company from the AIT Alert Data Set that the model
never trained on. Its queue for 2022-01-21:

```text
run russellmitchell-20261021-124402-413  |  company russellmitchell  |  budget 10  |  326 families
Review queue (top 10 per day, 2022-01-21)  |  F1 = top priority
┏━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━━┳━━━━━━━━┓
┃ handle ┃ date       ┃ start ┃ host            ┃ crit     ┃ detector ┃ finding                                  ┃ why                         ┃ alerts ┃ chain ┃ score ┃    esc% ┃ review ┃
┡━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━━╇━━━━━━━━┩
│ F1     │ 2022-01-21 │ 00:18 │ internal-share  │ high     │ AMiner   │ AMiner: New service_start parameter comb │ asset role internal         │      1 │     1 │  1.00 │         │        │
│ F2     │ 2022-01-21 │ 00:18 │ internal-share  │ high     │ AMiner   │ AMiner: New service_stop parameter combi │ asset role internal         │      1 │     1 │  1.00 │         │        │
│ F3     │ 2022-01-21 │ 00:14 │ internal-share  │ high     │ AMiner   │ AMiner: New event type.                  │ asset role internal         │      1 │     1 │  0.87 │         │        │
│ F4     │ 2022-01-21 │ 00:00 │ inet-firewall   │ critical │ AMiner   │ AMiner: New ip address in DNS logs.      │ asset role firewall         │     16 │     2 │  0.30 │         │        │
│ F5     │ 2022-01-21 │ 06:33 │ inet-firewall   │ critical │ AMiner   │ AMiner: Unusual occurrence frequencies o │ asset role firewall         │      6 │     2 │  0.20 │         │        │
│ F6     │ 2022-01-21 │ 06:33 │ intranet-server │ high     │ Suricata │ ET POLICY GNU/Linux APT User-Agent Outbo │ detectors within 10 minutes │      7 │     2 │  0.18 │         │        │
│ F7     │ 2022-01-21 │ 00:01 │ intranet-server │ high     │ AMiner   │ AMiner: CPU value out of expected range  │ detectors within 10 minutes │     15 │     2 │  0.18 │         │        │
│ F8     │ 2022-01-21 │ 06:37 │ webserver       │ high     │ Suricata │ SURICATA TLS invalid record/traffic      │ detectors within 10 minutes │    105 │     1 │  0.16 │         │        │
│ F9     │ 2022-01-21 │ 06:37 │ webserver       │ high     │ Suricata │ SURICATA TLS invalid handshake message   │ detectors within 10 minutes │    105 │     1 │  0.15 │         │        │
│ F10    │ 2022-01-21 │ 06:37 │ mail            │ high     │ Suricata │ SURICATA TLS invalid record/traffic      │ detectors within 10 minutes │    105 │     1 │  0.14 │         │        │
└────────┴────────────┴───────┴─────────────────┴──────────┴──────────┴──────────────────────────────────────────┴─────────────────────────────┴────────┴───────┴───────┴─────────┴────────┘
```

`score` sets the order and `why` names what raised it most.

<p align="center">
  <img
    src="docs/assets/demo.gif"
    alt="Terminal recording: meerkat demo, queue, inspect F1, review F2 benign, queue again with the decision shown, export decisions and export navigator"
    width="100%"
  >
</p>

## Daily use

Set the environment once in `meerkat.toml`:

```toml
environment = "acme"
inventory = "inventory/acme.json"
```

```bash
meerkat inventory --input alerts/2026-10-05 --out inventory/acme.json  # once
meerkat check --input alerts/2026-10-05      # what triage will see
meerkat pull --day 2026-10-06 --input alerts/2026-10-06  # each morning, yesterday
meerkat triage --input alerts/2026-10-06     # score the day into a run
meerkat browse                               # work the queue, record decisions
meerkat export decisions                     # the review pass as a grid
meerkat retrain --incidents tickets.csv      # refit on your own history
```

The [manual](docs/manual.md) covers every command and input format.

## How it works

- Alerts from one rule on one machine, with no gap over ten minutes, form a
  **session**.
- Sessions from the same day, machine, detector and rule form a **family**.
  One family is one line in the queue.
- A random forest scores each session. A logistic regression ranks each family
  from its sessions.
- The top ten families of each day are the queue.

<p align="center">
  <img
    src="docs/assets/pipeline.svg"
    alt="36,358 alerts group into 1,487 sessions, collapse into 326 daily families, and are cut to the 40 reviewed at a budget of 10 a day, which is a setting"
    width="100%"
  >
</p>

`meerkat retrain` refits the forest on your own incident history. It saves the
new model only if it passes a check against the shipped one on held-out days.

## Results

Tested on the [AIT Alert Data Set](https://zenodo.org/records/8263181): eight
simulated company networks hit by the same scripted attack, with every alert
labelled. The model trains on seven networks and is tested on the eighth, once
for each network.

| Ranking | attack steps found, 10 a day |
|---|---:|
| **Meerkat** | **57** |
| Forest score alone | 48 |
| Detector severity | 33 |
| Random order | 30 |

An attack step is one phase of the attack on one machine. It counts as found
when the queue holds one of its alerts. 60 steps can be found at all. The
busiest day, 453,697 alerts, takes 72 seconds and 1.1 GB of memory.
[bench/README.md](bench/README.md) shows how to reproduce these numbers.

## Limitations

- Every number comes from one simulated lab whose eight networks share one
  attack script. They say nothing about production.
- The shipped model knows only the lab's rules and asset roles. A new site
  should retrain on its own incident history. `check` and `triage` warn when
  more than 20% of alerts come from rules the model has not seen.
- An attack that fires the same rule as everyday noise, at the same severity
  and the same hours, ranks with the noise.

## License

MIT, see [LICENSE](LICENSE). [NOTICE](NOTICE) carries the AIT and MITRE ATT&CK
attributions and the data set references.

# meerkat manual

- [Install](#install)
- [Quickstart](#quickstart)
- [Inputs](#inputs)
- [Commands](#commands)
- [The model](#the-model)
- [Reproducing the results](#reproducing-the-results)
- [Limitations](#limitations)

## Install

Python 3.11 or newer. Meerkat is pure Python, so the same install works on
Linux, macOS and Windows.

From a clone, the full experience: the trained model, one campaign of example
alerts and the benchmark. Git LFS stores the large files.

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
git lfs install && git lfs pull
python -m pip install -e .
meerkat demo
```

From the release files: the `.whl` is the built package, and
`pip install meerkat-1.1.0-py3-none-any.whl` installs it. The `.tar.gz` is the
same code as a source archive, and pip installs it the same way.
`py3-none-any` in the wheel name says the file is pure Python and serves every
operating system. A wheel install brings the CLI and the ATT&CK lookup,
nothing else: the demo alerts, the trained bundle and the benchmark stay in
the repository, so a wheel install suits a deployment that brings its own
alerts and model bundle.

## Quickstart

`meerkat demo` scores the bundled example with the shipped model and prints
the first day's queue. Every later command reopens that saved run.

For your own alerts, put the detector exports in a directory named `alerts`,
then:

```bash
meerkat inventory        # write a starter asset inventory, fill in the roles
meerkat check            # report what triage will see, fix what it flags
meerkat triage           # score the batch into a run
meerkat queue            # the ranked queue
meerkat browse           # work it: drill into families, record decisions
meerkat export decisions # the review pass as a grid, for handoff
```

One run covers complete days; score a batch after the day closes, not during
it.

## Inputs

### Alert files

Meerkat looks in the input directory (default `./alerts`) for
`<environment>_wazuh.json` and `<environment>_aminer.json`, then falls back to
reading each `.json` file's opening lines to recognise its format. Every
recognised file is read, including a native Suricata `eve.json` beside a Wazuh
export. `--wazuh-file` and `--aminer-file` read only the named file. Wazuh and
Suricata are enough to run; AMiner improves coverage. A Suricata alert
forwarded by Wazuh and present in `eve.json` too is counted once.

### The inventory

One asset per machine, as JSON. `meerkat inventory` scaffolds it from the
Wazuh alerts; the roles are yours to fill in, and the model reads asset role
as a feature:

```json
{
  "company": "alerts",
  "assets": [
    { "hostname": "mail", "ip_addresses": ["172.19.130.4"],
      "roles": ["mail_server", "internet_facing"] }
  ]
}
```

`meerkat inventory --list-roles` prints the vocabulary, which follows OCSF
names. Assets with no role are scored without it.

### Incident records, for retraining

A CSV export from your ticketing system, one row per incident:

| column    | format                                                             |
| --------- | ------------------------------------------------------------------ |
| `start`   | epoch seconds or ISO 8601; a time without a timezone counts as UTC |
| `end`     | same, and not before `start`                                       |
| `host`    | a hostname or IP address from the inventory                        |
| `verdict` | `malicious`, `security_risk`, `test` or `true_positive`            |

```csv
start,end,host,verdict
2022-01-18T11:20:00Z,2022-01-18T13:05:00Z,intranet-server,true_positive
1642545600,1642552800,mail,malicious
```

The verdict names follow OCSF's Incident Finding, matched after lowercasing.
Rows with any other verdict are treated as non-attacks and dropped. A host the
inventory cannot resolve is named in a warning and its rows match nothing.

A first training batch should be the full alert archive with its incident
history; records covering about 15 distinct incidents are a comfortable
start. Keep the whole archive for later retrains, and trim old data only when
`meerkat drift` reports a major shift.

### Configuration

`meerkat.toml` in the working directory and `MEERKAT_*` variables fill flags
that were not passed. Flags beat variables, variables beat the file. The keys
are `environment`, `input`, `inventory`, `model` and `runs_dir`. `demo`
ignores both.

## Commands

Every command takes `--help`. Exit codes: 0 success, 1 error, 2 usage,
3 retrain refused, 4 major drift.

### demo

Scores the bundled example alerts and prints the first day's queue. Needs the
repository clone with Git LFS fetched. `--budget` sets families per day,
default 10. The demo ignores configuration, so it always scores the same
input the same way.

### inventory

Writes a starter asset inventory from the Wazuh alert file, one asset per
machine that reports an `agent.ip`. `--out` defaults to
`<input>/inventory/<environment>.json`; `--list-roles` prints the vocabulary.
Recorded output:

```text
wrote /tmp/inv.json  11 assets from 462523 alert lines
roles are empty  the model reads asset role as a feature; assets left without one are scored without
it
roles available: server, desktop, laptop, tablet, mobile, virtual, iot, browser, firewall, switch,
hub, router, ids, ips, load_balancer, internet_facing, internal, dmz, behind_proxy, nat_forwarded,
mail_server, dns_server, file_share, monitoring_agent, employee, internal_employee, remote_employee,
external_user, external_mail
```

### check

Reports what triage will see before running it, from a bounded sample
(`--sample`). It exits non-zero if inventory assets have no roles, if a role
name is outside the vocabulary, if the rule ids look like one per alert, or
if the alerts do not parse. Alerts on machines outside the inventory are a
warning, not an error. `--json` for scripts.

```text
reading up to 5000 alerts from data/raw
  found log anomaly         russellmitchell_aminer.json  3.4 MB
  found wazuh and suricata  russellmitchell_wazuh.json  45.3 MB
check (5000 alerts sampled)
┏━━━━━━━━━━┳━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ detector ┃ alerts ┃ hosts ┃ in inventory ┃ distinct rules ┃
┡━━━━━━━━━━╇━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ AMiner   │   2500 │    10 │    2500/2500 │             34 │
│ Suricata │    942 │     6 │      942/942 │              3 │
│ Wazuh    │   1558 │     9 │    1558/1558 │              9 │
└──────────┴────────┴───────┴──────────────┴────────────────┘
  covering 2022-01-21 00:00:01 to 2022-01-24 03:58:05
ready to triage
```

### triage

Scores one batch into a run under `runs/`; every later command reopens the
saved run. `--input`, `--inventory`, `--budget`, `--model`, `--environment`
as in [Inputs](#inputs). Run directories carry a timestamp and are never
overwritten.

### queue

Prints the ranked queue and exits. `score` sets the order. `esc%` fills in as
you review: how often you escalated your past reviewed families at the same
score, with the count; a fresh environment shows the score alone. Filters:
`--day`, `--host`, `--detector`, `--rule` (substring), `--review-state`,
`--all`. `--budget` re-cuts a saved run at a different K without rescoring.
`--json` for scripts. Recorded output:

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

### inspect

Opens one family (`F3`), a session inside it (`F3 S1`), or one alert
(`F3 S1 A2`). Power flags: `--where field=value` and `--exclude field=value`
filter the alert slice, `--distinct field` counts values, `--alerts N` sizes
the table, `--raw` prints the source lines as the detector wrote them. Long
output pages on a terminal that has a pager; `--no-pager` prints. A wrong
field name prints the fields that exist. Recorded output:

```text
run russellmitchell-20260724-230029  |  company russellmitchell  |  budget 10  |  326 families

F212  intranet-server / Suricata / ET SCAN Possible Nmap User-Agent Observed

Overview
  entity        : 10.143.2.4
  asset         : beatservers, intranet, servers
  rule          : 2024364
  window        : 2022-01-24 03:57:01  ->  2022-01-24 03:57:01  (0s)
  ranking score : 1.000
  volume        : 6 alerts, 1 session
  outcome       : 6 requests, none succeeded (404)

Ranking signals
  - best child session score 0.98
  - 3 detectors active on this host within 10 minutes

Sessions  |  S1 = strongest
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━┓
┃ handle ┃ start               ┃ span ┃ alerts ┃ score ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━┩
│ S1     │ 2022-01-24 03:57:01 │ 0s   │      6 │  0.98 │
└────────┴─────────────────────┴──────┴────────┴───────┘
drill into one with `meerkat inspect F212 S1`

Finding / Detection
      rule : 2024364
  severity : 1
  category : Web Application Attack

Network
        source ip : 172.19.131.174
          dest ip : 10.143.2.4
      source port : 38710, 38700, 38732
        dest port : 80
        transport : tcp
        app proto : http
  bytes to server : 910, 468, 449
  bytes to client : 632, 566

Network / HTTP
     request : /sdk, /nmaplowercheck1642996621, /HNAP1
      method : POST, GET
      status : 404
    hostname : intranet.smith.russellmitchell.com
  user agent : Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)

Provenance
         detector : suricata
      source file : russellmitchell_wazuh.json
  source position : 25427, 25430, 25432, 25434, 25446, 25448

Related ATT&CK observations
  intranet-server: Reconnaissance (03:57:01)
  tactics mapped independently

Related families on this host
  F218  Wazuh / Web server 400 error code.  score 1.00  other detector
  F210  AMiner / AMiner: New event type.  score 1.00  other detector
  F274  Wazuh / sshd: insecure connection attempt (scan).  score 0.05  other detector
  F213  AMiner / AMiner: New characters in Apache Access request.  score 1.00  other detector
  F214  AMiner / AMiner: New status code in Apache Access log.  score 1.00  other detector
  F220  Wazuh / Multiple web server 400 error codes from same source ip.  score 1.00  other detector
```

### review

Records a decision on a family or one of its sessions:

```bash
meerkat review F3 benign --note "known scanner"
meerkat review F3 escalate --session S1 --note "unexpected service change"
```

Decisions land in the run's `reviews.jsonl`, append-only; the last entry
covering a scope wins. A session review covers its alerts; a family review
covers every session without its own. Escalating a family with several
sessions requires `--session`, since that is the unit the model learns from.
`--analyst` names who decided, defaulting to the login name.

### browse

Prints the queue, then reads commands at a `browse>` prompt. The review pass
lives here:

```
browse> F3                      open a family
browse> S1                      open a session inside it
browse> A2                      open one alert
browse> review benign noisy dev box
browse> b                       back up one level
browse> all                     every scored family
browse> queue                   back to the budgeted view
browse> q                       quit
```

`review` acts on whatever is open. Decisions land in the same `reviews.jsonl`
as `meerkat review`.

### retrain

Refits the session forest on your own alert archive, supervised by your
incident records. Trains on the earlier days, scores itself on the most
recent ones, and saves a bundle only when a majority of its fits beat the
shipped one there. A refused retrain exits with code 3 and says why; nothing
is saved. A saved retrain prints what was refit, what was rescaled and what
was kept, and the bundle's provenance sidecar records every setting.

`--refit-ranking-weights` also fits the family ranking weights on your
incidents, keeping them only when they beat the shipped ones on the held-out
days. Below about 15 positive families the run warns and continues.

Other flags: `--holdout-days` (default 7), `--reviewed-periods` for a CSV of
fully reviewed periods, and tuning (`--trees`, `--seed`, `--fits`,
`--min-positives`, `--prior-k`, `--budget`) defaulting to the shipped
model's settings.

### drift

Reports whether the incoming alerts have changed shape since the model was
trained, with no labels needed: a population stability index per feature,
the share of rules the model never saw, and inventory coverage. PSI below
0.10 counts as stable, above 0.25 as a major shift; a major shift exits with
code 4. It does not report whether the ranking got worse, which needs
labelled outcomes. Recorded output:

```text
note the bundled model was trained with a different scikit-learn than the installed 1.9.0. It loads
and scores normally; retrain with `meerkat retrain` to silence this.
36358 alerts, 1487 sessions, 326 families against a model trained on 14292 sessions
  rules the model never saw: 0.0% of alerts
  sessions on hosts outside the inventory: 0.0%  (training had 0.4%)
feature drift, worst first
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ feature              ┃   PSI ┃ verdict  ┃ training median ┃     now ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ log_alerts_on_entity │ 1.897 │ major    │           7.364 │   6.894 │
│ groups_on_entity     │ 0.351 │ major    │          45.000 │  53.000 │
│ log_rarity           │ 0.160 │ moderate │          -8.940 │ -11.519 │
└──────────────────────┴───────┴──────────┴─────────────────┴─────────┘
  top-decile family score: 0.998 now, 0.900 at training
2 feature(s) past PSI 0.25  this reports that the input moved. It does not measure whether the
ranking is still right, which needs confirmed outcomes.
```

### export

Four exports, all from a saved run. `export decisions` is the review pass as
a grid, one row per alert with the decision it inherits and who made it;
`--decided-only` keeps the handoff summary, `--format csv|json`. `export
html` is the review pass as one self-contained page: escalations with their
evidence, closed families one line each, the rest listed unreviewed; with a
handle, one family's page. `export queue --format csv|json` feeds a ticketing
system or a spreadsheet. `export navigator` writes an ATT&CK Navigator layer,
`--queue-only` to keep queued families.

### runs

Lists the saved runs. The newest successful run is what every other command
opens by default; `--run` picks another. A run is a directory under `runs/`;
deleting the directory deletes the run and its reviews.

### completion

Prints a bash completion script harvested from the argument parser, so it
never drifts from the real flags. `meerkat completion >> ~/.bashrc`.

## The model

Four stages run between the raw files and the queue. **Normalise**: one table
from three detector formats, a shared severity scale, every alert attached to
an inventory asset. **Group**: alerts become sessions, sessions become daily
families. **Score sessions**: a random forest gives each session a
probability. **Rank families**: a logistic regression scores each family from
its sessions' scores, the family's shape and the machine's role; the highest
scores become the day's queue.

The forest, the inventory, the drift baseline and the `esc%` statistics come
from your environment. The family ranking weights ship pre-trained, fitted
across several environments, because a single campaign of incidents is too
little to fit them honestly; `retrain --refit-ranking-weights` contests them
on your own incidents. The `esc%` column is not a model output at all: it is
your own review history, counted per score band.

Retraining learns from incident windows rather than per-alert verdicts,
because that is what a SOC can write down: sessions inside a reported
incident share the weight of one label, sessions outside every incident are
the negatives, and the gate keeps any refit that does not beat the shipped
bundle from being saved.

## Reproducing the results

The benchmark lives in `bench/` in the repository and is not part of the
installed package. Reproduction needs the AIT Alert Data Set, a 2.7 GB
download; [bench/README.md](../bench/README.md) carries the steps, the layout
check and the expected numbers. `bench/digest.py` says in seconds whether a
code change moved the normalized frame.

## Limitations

**Batch, not streaming.** One run covers complete days; meerkat does not tail
a live alert stream.

**The labels are weak by design.** Incident windows, not per-alert verdicts.
The retrain gate compensates.

**Three detectors.** Wazuh, Suricata and AMiner. Others would need their own
normalisation.

**`esc%` needs history.** A fresh environment shows the score alone until
reviews accumulate.

**Evaluation is testbed data.** The published numbers come from the AIT Alert
Data Set and a cross-check on CAM-LDS; no production SOC data was available.

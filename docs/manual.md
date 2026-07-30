# meerkat manual

Meerkat is an open-source triage tool built as a research project. This manual says what each command does and what each input must look like.

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

### Model files

Model bundles are [skops](https://skops.readthedocs.io/) files: loading one
rebuilds only allowlisted types, so it does not execute the file the way
unpickling does. None of that makes an untrusted bundle safe, so load your
own. The JSON sidecar records the training settings and a checksum, which
catches corruption and proves nothing about who wrote the file. Run directories under `runs/` are
plain pickles; open only your own.

## Quickstart

`meerkat demo` scores the bundled example with the shipped model and prints the first day's queue. Every later command reopens the saved run.

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

One run covers complete days; score a batch after the day closes.

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

`meerkat inventory --list-roles` prints the vocabulary, which follows OCSF names. Assets with no role are scored without it. An alert spans several lines in the export, so the line counts the tool reports are larger than the alert counts.

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
that were not passed. Flags override variables, and variables override the file. The keys
are `environment`, `input`, `inventory`, `model` and `runs_dir`. `demo`
ignores both.

## Commands

Every command takes `-h`/`--help`. `--version` prints the version. `--no-color`
gives plain output, and the `NO_COLOR` environment variable does the same.

Commands that open a saved run share two options: `--run RUN` picks a run id
and defaults to the latest successful one, `--runs-dir DIR` names the
directory runs are saved in. Commands that read alerts share the openers
described in [Inputs](#inputs): `--environment`, `--input`, `--inventory`,
`--wazuh-file`, `--aminer-file`.

Exit codes:

| code | meaning |
| --- | --- |
| 0 | success |
| 1 | error |
| 2 | bad arguments |
| 3 | retrain refused by the gate |
| 4 | major feature drift, or too many rules the model never saw |

---

### meerkat demo

Score the bundled example alerts and print the first day's queue. Needs the
repository clone with Git LFS fetched.

    meerkat demo [--raw-dir DIR] [--model FILE] [--budget K] [--runs-dir DIR]

| option | description |
| --- | --- |
| `--raw-dir DIR` | where the bundled alerts live, default `data/raw` |
| `--model FILE` | model bundle, default `models/meerkat_bundle.skops` |
| `--budget K` | families reviewed per day, default 10 |
| `--runs-dir DIR` | where the run is saved, default `runs/` |

The demo ignores `meerkat.toml` and `MEERKAT_*` variables, so it always
scores the same input the same way.

---

### meerkat inventory

Write a starter asset inventory from the Wazuh alert file, one asset per
machine that reports an `agent.ip`. Roles are left empty; fill them in.

    meerkat inventory [ENVIRONMENT] [--input DIR] [--out FILE]
                      [--limit N] [--list-roles]

| option | description |
| --- | --- |
| `ENVIRONMENT` | run label; defaults to the input directory's name |
| `--input DIR` | directory holding the alert files, default `./alerts` |
| `--out FILE` | default `<input>/inventory/<environment>.json` |
| `--limit N` | stop after this many alert lines |
| `--list-roles` | print the role vocabulary and where each name comes from |

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

---

### meerkat check

Report what triage will see before running it: per-detector counts, inventory
match rate, role coverage and rule cardinality, from a bounded sample. Exits
non-zero when assets have no roles, a role name is outside the vocabulary,
rule ids look numbered per alert, or the alerts do not parse. Alerts on
machines outside the inventory are a warning; the run still passes.

    meerkat check [--environment NAME] [--input DIR] [--inventory FILE]
                  [--sample N] [--json] [--wazuh-file FILE] [--aminer-file FILE]

| option | description |
| --- | --- |
| `--sample N` | how many alerts to read, default 5000 |
| `--json` | the report as JSON; warnings stay on stderr |
| `--environment`, `--input`, `--inventory` | the shared openers |
| `--wazuh-file FILE`, `--aminer-file FILE` | read only the named file |

Recorded output:

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

---

### meerkat triage

Score one batch of alerts into a run under the runs directory. Every later
command reopens the saved run instead of scoring again. Run directories carry
a timestamp and are never overwritten.

    meerkat triage [--environment NAME] [--input DIR] [--inventory FILE]
                   [--budget K] [--model FILE] [--runs-dir DIR]
                   [--wazuh-file FILE] [--aminer-file FILE] [--labels FILE]

| option | description |
| --- | --- |
| `--budget K` | families reviewed per day, default 10 |
| `--model FILE` | model bundle, default `models/meerkat_bundle.skops` |
| `--runs-dir DIR` | where runs are saved, default `runs/` |
| `--labels FILE` | optional label CSV, for evaluation only |
| `--event-csv-dir DIR` | benchmark label directory, evaluation only |
| `--environment`, `--input`, `--inventory` | the shared openers |
| `--wazuh-file FILE`, `--aminer-file FILE` | read only the named file |

---

### meerkat queue

Print the ranked queue of a saved run and exit. `score` sets the order.
`esc%` fills in as you review: how often you escalated your past reviewed
families at the same score, with the count; a fresh environment shows the
score alone.

    meerkat queue [--all] [--host HOST] [--detector NAME] [--rule TEXT]
                  [--review-state STATE] [--day YYYY-MM-DD] [--budget K]
                  [--json] [--run RUN] [--runs-dir DIR]

| option | description |
| --- | --- |
| `--all` | every scored family |
| `--host HOST` | filter by host or entity |
| `--detector NAME` | filter by detector source |
| `--rule TEXT` | filter by rule id substring |
| `--review-state STATE` | families whose decision matches: `escalate`, `benign` or `false-positive` |
| `--day YYYY-MM-DD` | one day's queue |
| `--budget K` | re-cut the saved run at a different K; no rescoring |
| `--json` | the queue as JSON |
| `--no-pager` | accepted for consistency; queue never pages |

Recorded output:

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

---

### meerkat inspect

Open one family, one session inside it, or one alert.

    meerkat inspect HANDLE [SESSION] [ALERT] [--where FIELD=VALUE]
                    [--exclude FIELD=VALUE] [--distinct FIELD] [--alerts N]
                    [--raw] [--raw-dir DIR] [--json] [--no-pager]
                    [--run RUN] [--runs-dir DIR]

| option | description |
| --- | --- |
| `HANDLE` | a family, e.g. `F3` |
| `SESSION` | a session inside it, e.g. `S1` |
| `ALERT` | one alert, e.g. `A2`; shows its full record |
| `--where FIELD=VALUE` | keep alerts matching a field; repeatable |
| `--exclude FIELD=VALUE` | drop alerts matching a field; repeatable |
| `--distinct FIELD` | count the distinct values of one field |
| `--alerts N` | show up to N alert rows |
| `--raw` | print the source lines as the detector wrote them |
| `--raw-dir DIR` | where the alert files live; defaults to what the run recorded |
| `--json` | the family, sessions and alerts as JSON |
| `--no-pager` | print without the pager |

Long output pages on a terminal that has a pager. A wrong field name prints
the fields that exist. Recorded output:

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

---

### meerkat review

Record a decision on a family or one of its sessions. Decisions are appended to the run's `reviews.jsonl`; the last entry covering a scope wins. A
session review covers its alerts; a family review covers every session
without its own.

    meerkat review HANDLE DECISION [--session S] [--note TEXT]
                   [--analyst NAME] [--run RUN] [--runs-dir DIR]

| option | description |
| --- | --- |
| `HANDLE` | the family, e.g. `F3` |
| `DECISION` | `escalate`, `benign` or `false-positive` |
| `--session S` | which burst, e.g. `S1`, or `all`; required to escalate a family with several sessions |
| `--note TEXT` | free text stored with the decision |
| `--analyst NAME` | who decided; defaults to the login name |

---

### meerkat browse

Print the queue, then read commands at a `browse>` prompt. The review pass
lives here.

    meerkat browse [--run RUN] [--runs-dir DIR]

| prompt input | effect |
| --- | --- |
| `F3` | open a family |
| `S1` | open a session inside the open family |
| `A2` | open one alert inside the open session |
| `review DECISION [note]` | record a decision on what is open |
| `b` | back up one level |
| `all` | every scored family |
| `queue` | back to the budgeted view |
| `q` | quit |

Decisions are appended to the same `reviews.jsonl` as `meerkat review`, with the same rules.

---

### meerkat retrain

Refit the session forest on your own alert archive, supervised by your
incident records. Trains on the earlier days, scores the last `--holdout-days`,
and saves only when a majority of the fits beat the shipped bundle there. A
refusal exits with code 3 and says why; nothing is saved. A saved retrain
prints what was refit, rescaled and kept, and the bundle's provenance sidecar
records every setting.

    meerkat retrain --incidents FILE --inventory FILE [--input DIR]
                    [--environment NAME] [--out FILE] [--holdout-days N]
                    [--budget K] [--model FILE] [--reviewed-periods FILE]
                    [--refit-ranking-weights] [--prior-k K] [--min-positives N]
                    [--trees N] [--seed N] [--fits N]
                    [--wazuh-file FILE] [--aminer-file FILE]

| option | description |
| --- | --- |
| `--incidents FILE` | CSV of `start,end,host,verdict`, required; format in [Inputs](#inputs) |
| `--inventory FILE` | required; incidents name hosts through it |
| `--out FILE` | where the new bundle is written |
| `--holdout-days N` | days held out for the comparison, default 7 |
| `--budget K` | budget the comparison scores at, default 10 |
| `--model FILE` | bundle to start from; `--refit-ranking-weights` can replace its ranking weights |
| `--reviewed-periods FILE` | CSV of `start,end` periods whose alerts were fully reviewed; only sessions inside them can count as negatives |
| `--refit-ranking-weights` | also fit the family ranking weights on your incidents; adopted only if they beat the shipped ones on the held-out days. Below about 15 positive families the run warns and continues |
| `--prior-k K` | bag-size discount; a ticket contributes k/n per session, default 1 |
| `--min-positives N` | bagged sessions needed before any fit, default 10 |
| `--trees N` | trees per forest, default 200, matching the shipped model |
| `--seed N` | base random seed, default 0 |
| `--fits N` | forests fitted; a majority must beat the shipped one, default 5 |

---

### meerkat drift

Report whether the incoming alerts have changed shape since the model was
trained, with no labels needed: a population stability index per feature, the
share of rules the model never saw, and inventory coverage. PSI below 0.10 is
stable, above 0.25 is a major shift; a major shift exits with code 4. It does
not report whether the ranking got worse, which needs labelled outcomes.

    meerkat drift [--environment NAME] [--input DIR] [--inventory FILE]
                  [--model FILE] [--top N] [--all] [--json]
                  [--wazuh-file FILE] [--aminer-file FILE]

| option | description |
| --- | --- |
| `--top N` | how many features to list |
| `--all` | every feature, stable ones included |
| `--json` | the full report as JSON, every feature included |
| `--model FILE` | the bundle whose training profile is the baseline |

Recorded output:

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

---

### meerkat export

Four exports, all from a saved run. Each takes `--run` and `--runs-dir`.

    meerkat export queue     [--format csv|json] [--output FILE] [--all]
    meerkat export decisions [--format csv|json] [--output FILE] [--all]
                             [--decided-only]
    meerkat export html      [HANDLE] [--output FILE]
    meerkat export navigator [--output FILE] [--queue-only]

| option | description |
| --- | --- |
| `queue --format` | the queue as `csv` or `json`, for a ticketing system |
| `decisions` | the review pass as a grid: one row per alert with the decision it inherits, who made it, and the note |
| `decisions --decided-only` | only rows carrying a decision; the handoff summary |
| `html [HANDLE]` | the review pass as one self-contained page: escalations with evidence, closed families one line each, the rest listed unreviewed. With a handle, one family's page |
| `navigator` | an ATT&CK Navigator layer of the run, every alert in it |
| `navigator --queue-only` | only alerts of families that entered the queue |
| `--all` | every scored family, not only the daily top K |
| `--output FILE` | where the file is written, default inside the run directory |

---

### meerkat runs

List the saved runs: id, environment, budget, days, families, saved at. The
newest successful run is what every other command opens by default.

    meerkat runs [--runs-dir DIR] [--json]

| option | description |
| --- | --- |
| `--json` | the list as JSON |
| `--no-pager` | accepted for consistency; runs never pages |

A run is a directory under `runs/`; deleting the directory deletes the run
and its reviews.

---

### meerkat completion

Print a bash completion script generated from the argument parser, so it always matches the real flags. Covers command names, flags, and the `export` subcommands.

    meerkat completion >> ~/.bashrc

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
small a sample for a stable fit; `retrain --refit-ranking-weights` refits
them on your own incidents and keeps whichever set scores better. The `esc%` column comes from your own review
history, counted per score band.

Retraining learns from incident windows, because that is what a SOC can write down: sessions inside a reported
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

**Batch.** One run covers complete days; meerkat does not tail a live
alert stream.

**The labels are coarse.** Retraining learns from incident windows, and the retrain gate compensates.

**Three detectors.** Wazuh, Suricata and AMiner. Others would need their own
normalisation.

**`esc%` needs history.** A fresh environment shows the score alone until
reviews accumulate.

**Evaluation is testbed data.** The published numbers come from the AIT Alert
Data Set and a cross-check on CAM-LDS; no production SOC data was available.

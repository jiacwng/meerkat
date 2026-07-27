# bench

This directory reproduces the published evaluation numbers on the AIT Alert Data
Set. It needs an external download of eight simulated company environments, 2.7 GB
of alert JSON that no clone of this repository carries. None of it is needed to
*use* meerkat: `meerkat demo`, `meerkat triage` and the shipped model bundle in
`models/` work with nothing from here, and no module under `core/` or `meerkat/`
imports `bench`.

Only russellmitchell ships in the repository, its two alert files at 48 MB through
Git LFS, to drive the demo. `.gitignore` excludes the other seven environments, so
**the benchmark cannot be reproduced from a clone alone**. Download the dataset
first.

## What you need

The AIT Alert Data Set, Zenodo record [8263181](https://zenodo.org/records/8263181),
DOI `10.5281/zenodo.8263181`, published by the Austrian Institute of Technology
under CC BY 4.0. The archive holds sixteen files, two per environment, and unpacks
to 2.7 GB. Plan on 3.6 GB of free disk if you keep the archive beside the unpacked
files.

The eight environment names, spelled as the files spell them: `fox`, `harrison`,
`russellmitchell`, `santos`, `shaw`, `wardbeck`, `wheeler`, `wilson`.

Unpack the alert files into `data/raw/`:

```text
data/
├── labels.csv                       attack windows, already in the repo
└── raw/
    ├── fox_wazuh.json               Wazuh + Suricata alerts, required
    ├── fox_aminer.json              AMiner log-anomaly alerts, optional
    ├── harrison_wazuh.json
    ├── harrison_aminer.json
    ├── ...                          one pair per environment
    ├── wilson_wazuh.json
    ├── wilson_aminer.json
    └── inventory/
        ├── fox.json                 asset roles, already in the repo
        ├── ...
        └── wilson.json
```

`<name>_wazuh.json` carries the Wazuh alerts and the Suricata alerts together,
because Wazuh collects Suricata's `eve.json`. `<name>_aminer.json` is the third
detector and is optional per environment, at the cost in coverage listed under
detector ceilings below. The eight inventories and `data/labels.csv` are already
committed, so the sixteen alert files are the only thing to place.

## Reproducing

Three steps, in this order, from the repository root:

```bash
python -m bench.check
python -m bench.train --holdout russellmitchell
python -m bench.evaluate --trees 200 --seeds 53,52,51
```

`bench.check` runs first. It walks `data/raw/`, reports what it can see per
environment, and names every missing or unreadable file by path. Run it until all
eight environments come back clean. `train` and `evaluate` on a half-placed
dataset produce numbers that answer a different question.

## Deciding whether to re-run

`evaluate` reads 2.7 GB and fits twenty-four models, so it is worth knowing first
whether anything can have changed:

```bash
python -m bench.digest
```

It hashes every column of every row of the normalized frame for one environment.
The same digest means the same sessions, features, scores and queue, so the table
cannot have moved and there is nothing to re-run. It exits non-zero when the
digest differs from the recorded one, which is the signal to spend the hours. The
recorded value only needs the demo environment, so unlike the rest of `bench/` it
runs from a clone.

`bench.train` writes `models/meerkat_bundle.skops` and a `.skops.json` sidecar
recording the scikit-learn version, the training environments and a SHA-256 of
the bundle. `--holdout russellmitchell` is what the shipped bundle was built
with, and the sidecar in the repository lists the seven environments that
remain. russellmitchell drives the demo, so keeping it out of training means the
demo scores an environment the model never saw. Without the flag, `bench.train`
trains on all eight and produces a different bundle. It defaults to 200 trees,
the count past which coverage stopped improving. The shipped sidecar records 300,
because the bundle was built before that default changed.

`bench.evaluate` runs the leave-one-environment-out protocol and prints the
results table. It defaults to 200 trees, matching the table below, and to seed 0.
`--seeds 53,52,51` is the rest of what the table was measured with. It reads 2.7 GB and fits eight folds times three seeds, so it is the
long step. The largest single input is `wilson_wazuh.json` at 673 MB.

## Expected results

For each of the eight folds, seven environments train and the eighth is scored
unseen. The family re-ranker and the confidence calibrator are fitted out-of-fold
across environments, so the held-out environment feeds neither. Each cell counts
how many labelled attack windows the daily queue reaches at a review budget of K
families per day, averaged over seeds 53, 52 and 51 with 200 trees.

| Ranker | K=5 | K=10 | K=25 |
|---|---:|---:|---:|
| **Family re-ranker (ours)** | **51** | **58** | **58** |
| Best child session | 44 | 54 | 58 |
| Family size | 29 | 30 | 39 |
| Native detector severity | 19 | 33 | 46 |
| Random | 21 | 31 | 45 |

Detector ceilings bound every row above. Read a low number against its ceiling
before reading it as a ranking failure:

- All three detectors present: 60 of 60 attack windows reachable.
- Without the AMiner log-anomaly detector: 41 of 60. The other 19 windows are
  visible to AMiner alone and to no other detector.

## What reproducing does and does not prove

The ACM Artifact Review vocabulary, used the way ACM defines it:

- **Reproduced**: a different team obtains the stated result using the original
  artifacts. Running `python -m bench.evaluate` over the Zenodo dataset gets you
  Reproduced.
- **Replicated**: a different team obtains the stated result using their own
  artifacts, meaning their own data and their own implementation. Nothing in this
  directory reaches Replicated.

The evidence has a hard edge. Eight environments come out of one testbed
generator and share one attack script. A clean reproduction shows the table
follows from this code and this dataset. It supports no claim about a production SOC, whose alert mix, detector
tuning and asset roles all sit outside the sample. The eight folds are eight
draws from one generator, so treat the spread across folds as sensitivity to the
environment rather than as a confidence interval for the field.

## Kept out of the product

`core/` and `meerkat/` never import `bench`, and the installable package leaves
this directory out, so `pip install` of meerkat gives you the CLI and the model
bundle without the benchmark. Modules here run from a checkout only, called as
`python -m bench.<module>` from the repository root.

Meerkat is MIT licensed. The alert files are from AIT-ADS under CC BY 4.0, and
the repository ships one of the eight environments; `NOTICE` records what is
included and how to attribute it. Cite the dataset if you publish anything
from these numbers. The references sit in `CITATION.cff` at the repository root.

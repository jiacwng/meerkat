# bench

Reproduces the numbers in the README and builds the model in `models/`. It
needs the AIT Alert Data Set, which the clone does not carry: 2.7 GB of alerts
from eight simulated networks. Nothing in `core/` or `meerkat/` imports this
folder.

## Setup

Download the [AIT Alert Data Set](https://zenodo.org/records/8263181) (Zenodo
record 8263181, CC BY 4.0) and put its sixteen files in `data/raw/`, one pair
per network:

```text
data/raw/fox_wazuh.json       Wazuh and Suricata alerts, required
data/raw/fox_aminer.json      AMiner alerts, optional
...                           the same for harrison, russellmitchell, santos,
                              shaw, wardbeck, wheeler and wilson
```

The labels and the inventories are already in the repository. Without the
AMiner files, 41 of the 60 attack steps can be found.

## Run

From the repository root, with the pinned versions:

```bash
pip install -e . -c .github/constraints.txt
python -m bench.check
python -m bench.train --holdout russellmitchell
python -m bench.evaluate --trees 200 --seeds 53,52,51
```

`check` lists any missing file. `train` writes `models/meerkat_bundle.skops`
and leaves out russellmitchell, so the demo scores a network the model never
saw. `evaluate` trains on seven networks and tests on the eighth, once for each
network and each seed, then prints the table.

## Expected results

Attack steps found per review budget, averaged over the three seeds:

| Ranking | 5 a day | 10 a day | 25 a day |
|---|---:|---:|---:|
| **Meerkat** | **52** | **57** | **58** |
| Forest score alone | 41 | 48 | 58 |
| Family size | 29 | 30 | 39 |
| Detector severity | 19 | 33 | 46 |
| Random order | 21 | 30 | 44 |

The tree count, the re-ranker and the counting rule were chosen on these same
eight networks, so the table is a tuning result.

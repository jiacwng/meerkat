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

Meerkat reads alerts from Suricata, Wazuh and AMiner, normalizes them into one
common format, scores each alert with supervised models, maps it to MITRE
ATT&CK techniques and tactics, and produces a fixed size daily review queue.

Methods, experiments and measured results are documented in the technical
report: **[Meerkat: Alert Triage for Multi-Detector Security Operations Data](docs/report/meerkat.pdf)**.

## Installation

```bash
git clone https://github.com/jiacwng/meerkat.git
cd meerkat
pip install -r requirements.txt
```

Requires Python 3.11 or later.

## Dataset

Experiments use [AIT-ADS](https://zenodo.org/records/8263181) (Austrian
Institute of Technology, CC BY 4.0): eight simulated enterprise environments
monitored by Suricata, Wazuh and AMiner, each subjected to a scripted
multi step attack.

One environment ships with the repository, so the single environment example
below runs immediately after installation. The remaining data is optional:

| Task | Data required |
|---|---|
| Single environment training and evaluation | included (`data/ait_alerts.json`) |
| Cross environment evaluation | `ait_ads.zip` from Zenodo, extracted to `data/raw/` |
| Event label supervision and audit | `alerts_csv.zip` from the [project repository](https://github.com/ait-aecid/alert-data-set), extracted to `data/raw/alerts_csv/` |

Expected layout for the optional downloads:

```
data/raw/<scenario>_wazuh.json
data/raw/<scenario>_aminer.json
data/raw/alerts_csv/<scenario>_alerts.txt
```

## Usage

The command line interface is in development. Current entry points are the
library modules.

Load alerts, build features and train a model on one environment:

```python
from pathlib import Path
from core.normalize import normalize
from core.features import build_feature_matrix
from core.classifier import train, evaluate

alerts = normalize(Path("data/ait_alerts.json"), Path("data/labels.csv"))
matrix = build_feature_matrix(alerts)
model, holdout = train(matrix.X, matrix.attack_window)
report = evaluate(model, holdout)

print(report.window_recall, report.workload_reduction)
```

Evaluate across all eight environments, training on seven and testing on the
one held out:

```python
from core.scenario_eval import load_scenarios, evaluate_scenarios

frames = load_scenarios(Path("data/raw"), Path("data/labels.csv"))
report = evaluate_scenarios(frames)

print(report.summary)
```

Map alerts to ATT&CK and export a layer file for the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):

```python
from core.attack_mapping import map_alert, export_navigator_layer

mapping = map_alert("wazuh", "31516", "T1055")
print(mapping.technique_ids, mapping.tactics)
```

Verify the dataset labels before use:

```bash
python -m core.event_labels
```

## Modules

| Module | Purpose |
|---|---|
| `core/normalize.py` | Maps three detector schemas onto one alert table |
| `core/features.py` | Encodes alerts as numeric features |
| `core/classifier.py` | Random Forest ranking models and evaluation |
| `core/attack_mapping.py` | MITRE ATT&CK technique and tactic mapping |
| `core/triage_policy.py` | Priority bands and daily queue construction |
| `core/scenario_eval.py` | Leave one scenario out evaluation |
| `core/event_labels.py` | Official per alert label loading and audit |

## Status

Evaluated across eight simulated environments. The current model reaches 28 of
79 labelled attack windows and misses quiet attack phases; measured results and
their limitations are reported in full in the technical report. Packaging and
the command line interface are in progress.

## License

Code released under the MIT License. The AIT-ADS dataset is distributed
separately by the Austrian Institute of Technology under CC BY 4.0.

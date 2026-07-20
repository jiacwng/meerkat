<p align="center">
  <img
    src="docs/assets/meerkat-analyst.png"
    alt="Pixel-art meerkat security analyst reviewing an alert"
    width="334"
  >
</p>

<h1 align="center">Meerkat</h1>

<p align="center">
  <strong>From noisy security alerts to prioritized, explainable investigation context.</strong>
</p>

<p align="center">
  Meerkat estimates attack risk, prioritizes alerts, and enriches them
  with MITRE ATT&CK context.
</p>



# Meerkat

Meerkat is a small tool that looks at real security alerts from three different
detectors (Suricata, Wazuh, and AMiner) and tries to figure out which ones
actually deserve a human's attention. Modern security teams get buried in
thousands of alerts a day, and most of them are noise.
This project combines a bit of rule-based context (mapping alerts to MITRE ATT&CK tactics) with a
Random Forest classifier to help rank what matters. It's a learning project
built to understand how SOC (Security Operations Center) triage actually
works, end to end, on real data rather than a toy dataset.

## Cross-Environment Evaluation

Meerkat is evaluated with leave-one-scenario-out testing across all eight
AIT-ADS simulated enterprise environments. For each fold, seven scenarios are
used for training and validation, while the eighth remains completely unseen.
The primary model excludes direct host-name identity to reduce environment
memorization.

With the 300-tree Random Forest, the scenario-macro results are:

| Metric | Result |
|---|---:|
| Attack-window recall | 86.44% |
| Workload reduction | 54.13% |
| Outside-window review rate | 0.011% |

Performance is uneven: recall falls to 44.70% on the weakest held-out
scenario, and several sparse attack phases remain undetected. Also, an alert
outside a simulated attack window is not necessarily benign, so the
outside-window metric must not be interpreted as a confirmed false-positive
rate.

WIP

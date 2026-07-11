# Meerkat

Meerkat is a small tool that looks at real security alerts from three different
detectors (Suricata, Wazuh, and AMiner) and tries to figure out which ones
actually deserve a human's attention. Modern security teams get buried in
thousands of alerts a day, and most of them are noise.
This project combines a bit of rule-based context (mapping alerts to MITRE ATT&CK tactics) with a
Random Forest classifier to help rank what matters. It's a learning project
built to understand how SOC (Security Operations Center) triage actually
works, end to end, on real data rather than a toy dataset.

WIP

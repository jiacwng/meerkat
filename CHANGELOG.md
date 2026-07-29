# Changelog

## Unreleased

Scores unchanged: the normalized frame digest is `4b390168afda96bf` before and
after.

### Breaking

- `meerkat train` removed. Use `python -m bench.train`.
- `--company` is `--environment` now, on every command that takes it.
- `--input` defaults to `./alerts`, was `data/raw`.
- Model bundles must be skops. 1.0.0 bundles no longer load.

### Added

- `meerkat retrain`, from a CSV of `start,end,host,verdict`. Trains on earlier
  days, scores the last `--holdout-days`, and saves only when a majority of its
  forests reach at least as many unseen incidents as the shipped bundle and
  disagree with it on at least six of them. Ticket labels score 49 at budget 5
  against 51 with per-alert ground truth.
- `meerkat check`, reports per-detector counts, inventory match rate, role
  coverage and rule cardinality from a bounded sample.
- `meerkat drift`, reports input distribution change with no labels. Population
  stability index per feature, plus unseen-rule share and inventory coverage.
- `meerkat inventory`, scaffolds an asset inventory from the wazuh alert file,
  from the records that carry an `agent.ip`.
- `meerkat.toml` and `MEERKAT_*` variables fill flags that were not passed.
  Flags beat variables, variables beat the file. `demo` ignores both.
- Bare `meerkat` prints where things stand and the next commands, instead of a
  usage error.
- Handles are unpadded: `F1`, `S1`. Runs saved with padded handles still open.
- Alert handles: `inspect F3 S1 A2` opens one alert's full record, `--raw` adds
  the source line. Alert tables carry the handles.
- The family view always lists its sessions; every view prints the next
  command on stderr.
- `meerkat browse`, a prompt loop over the same views the commands print:
  type `F3`, `S1`, `A2` to drill, `review <decision> [note]` to record,
  `b` walks back, `q` quits. No extra dependencies, no alternate screen.
- `--no-color`, and `meerkat completion` prints a bash completion script.
- The queue shows each family's start time, and table titles say what the
  handle order means: F1 top priority, S1 strongest, A1 first in time.
- Alert tables carry the field that varies inside the session. Session views
  report native severity, burst shape and techniques.
- ATT&CK ids embedded in Suricata rule metadata are read as native techniques.
  Ids the lookup knows link to attack.mitre.org; nothing else becomes a link.
- Long `queue` and `inspect` output pages on a terminal that has a pager;
  `--no-pager` refuses.
- `drift --all` lists every feature. `retrain` reports every failed
  precondition in one run.
- `meerkat export decisions`, the review pass as a grid: one row per alert
  with the decision it inherits. A session review covers its alerts; a family
  review covers every session without its own; the audit order decides.
  `--decided-only` keeps the handoff summary.
- Every review records its analyst: the login name, or `--analyst`.
- `meerkat export queue --format csv|json`.
- `--json` on `queue`, `runs`, `inspect`, `check` and `drift`. The drift
  report carries every feature. Errors go to stderr.
- `queue --budget`, recuts a saved run without rescoring.
- Alert files resolved by name first, `<environment>_wazuh.json` and
  `<environment>_aminer.json`, then by format. Every recognised file is read,
  including a native Suricata `eve.json` beside a Wazuh export. `--wazuh-file`
  and `--aminer-file` read only the named file.
- `bench/digest.py`, says in seconds whether a change moved the normalized
  frame.
- The evaluation reports the alerts a queue contains and their share of the
  day, a one-item-per-day floor row, and exact sign tests per seed.
- OCSF-anchored role vocabulary. `--list-roles`.
- `bench/check`, verifies the benchmark layout.
- `CITATION.cff`.

### Security

- `load_model` accepts skops bundles only, and rejects types outside its
  allowlist.
- Alert-derived text is escaped and stripped of control characters before
  rendering. Affects rule names, hostnames, user agents, URLs and commands.
- `export queue --format csv` quotes cells starting with `=`, `+`, `-` or `@`.
- Run ids must be a single path component.
- The AMiner sudo pattern caps input at 4096 characters.

### Fixed

- A Suricata alert forwarded by Wazuh from `eve.json` is counted once when both
  files are present. Repeats inside one file are kept.
- Wazuh's own `timestamp` field is read beside Elastic's `@timestamp`.
- AMiner records are read without the `AMiner` wrapper; the wrapper comes from
  the export. The log path is read from `LogData.LogResources` beside
  `AnalysisComponent.LogResource`.
- A miner line with the wrapper but no analysis block stopped the whole ingest.
- `--help` and the read commands no longer import scikit-learn. Cold start drops
  from four seconds to under one; a test keeps it that way.
- Malformed alert lines, inventories and incident CSVs report the file and the
  problem instead of raising.
- The chunked alert reader behind `triage`, `check`, `drift` and `retrain` reads
  `utf-8-sig`, so a byte-order mark no longer stops a run. The format sniffer and
  `meerkat inventory` still read plain `utf-8`. Timestamps without a zone are
  read as UTC.
- Single-detector exports group correctly.
- `--budget` and `--prior-k` reject values that produce an empty or unweighted
  queue. `--input` must be an existing directory.
- Run directories carry milliseconds and never overwrite an existing run.
- `queue --rule` matches a substring, as documented.
- Commands that need a model report it before reading any alerts, and say whether
  the bundle is missing from the working directory or unfetched from Git LFS.
- A missing input directory is named as such rather than as a missing inventory.

### Changed

- The family view no longer prints `family_id`, a second run id, or the list
  of the panels it just printed.
- The README terminal captures use a flat style.
- CLI messages describe what the tool does with the input rather than instruct
  the operator, and figures measured on the benchmark stay in the report.
- `export navigator` documents its scope: a saved run, every alert in it by
  default, `--queue-only` for queued families.
- Exit codes: 0 success, 1 error, 2 usage, 3 retrain refused, 4 major feature
  drift or too many rules the model never saw.
- Benchmark harness moved to `bench/`. Not importable from the product, not in
  the installed package. Reproduction needs a 2.7 GB download, see
  [bench/README.md](bench/README.md).
- Normalisation reads in 10,000-row chunks.
- The log-anomaly detector is optional. Without one, 41 of 60 windows are
  reachable rather than 60.
- Bag-size discount default 2/n to 1/n. Ten paired seeds found no difference
  across 1/n to 5/n.
- Tests 137 to 405.

## 1.0.0

Alerts to sessions to daily families, random forest with a learned family
re-ranker, calibrated top-K queue. Leave-one-environment-out over eight simulated
company networks.

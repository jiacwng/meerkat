## What this changes

<!-- One paragraph. What the reader gets that they did not have before. -->

## Why

<!-- The problem, not the solution. If it fixes a defect, say how it reached a user. -->

## How it was verified

<!-- Commands and their output, not adjectives. For example:

    python -m unittest discover -s tests -q     Ran 334 tests   OK
    python -m ruff check core meerkat bench tests
    pip install . --target T --no-deps && python -c "import meerkat.cli"

If a published number could have moved, say which and show it did not. -->

## Risk

<!-- What could break, and what would show it. Delete if genuinely none. -->

- [ ] The queue is unchanged, or the change is described above and measured
- [ ] No CLI flag, default or exit code changed without saying so
- [ ] CHANGELOG.md updated

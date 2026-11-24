# Reproduce the checks

From a clean checkout, use a virtual environment with Python 3.11 or later.

```sh
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest -q -rs
python tools/robustness.py --seed 61 --count 120
python -m build
python tools/verify_distribution.py
```

The distribution check inspects archive members, installs each archive in its own environment and exercises the installed CLI and offline test suite. Dependency installation can use a trusted wheelhouse and PIP_NO_INDEX. Run outside a shared writable environment. No advisory lookup is needed.

## Pinned integration

Set up the five public reference revisions in a new directory outside the repository. This explicit developer setup uses GitHub and the package index. Runtime operations are offline.

```sh
python tools/install_references.py /absolute/disposable/references
export WORKBENCH_REFERENCES=/absolute/disposable/references
export WORKBENCH_INTEGRATION=1
export WORKBENCH_RESTIC=/absolute/trusted/restic
python -m pytest -q -rs
```

In PowerShell set the same variables via `$env:WORKBENCH_REFERENCES`, `$env:WORKBENCH_INTEGRATION` and `$env:WORKBENCH_RESTIC`. Use verified restic 0.20.0 for your platform. The Linux verification commands and pinned release hashes are in the integration workflow. Ordinary test runs explicitly skip the four upstream integration tests. The integration tests build a disposable repository, perform a full read and plan recovery into an empty directory. They never execute a restore.

Keep tests local and synthetic. Add a focused regression for any change that could admit conflicting evidence or clear an incomplete check. Preserve raw bytes and explain any changes to supported contracts.

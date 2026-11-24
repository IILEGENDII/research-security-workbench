# Development evaluation

The full local test run used CPython 3.14.7 on Windows. All six check types were exercised with synthetic inputs. The upstream commits and licenses are recorded in [integration contracts](integration-contracts.md). Core runtime dependencies are limited to the Python standard library. The installed integration environment used cryptography 50.0.2, cyclonedx-python-lib 11.12.0, pytest 9.2.0, Ruff 0.17.6, build 1.6.1 and restic 0.20.0.

| Cumulative phase gate | Passed | Skipped |
| --- | ---: | ---: |
| A, installation, help and version | 1 | 0 |
| B, policy and storage | 33 | 3 |
| C, pinned outputs, validation and receipts | 59 | 3 |
| D, assessment and comparison | 69 | 3 |
| E, fixed collectors including real integration | 73 | 3 |
| F, fixture scenarios and all pinned upstreams | 81 | 3 |
| Final review with upstream integration enabled | 88 | 3 |

The final integrated suite took 51.05 seconds. This Windows sandbox could not create hard links or symlinks. POSIX FIFOs are unavailable on Windows. Without the explicit upstream integration switch the fast suite passed 84 and skipped seven, including four separately exercised integration cases.

The fixture workflow produced required assessment exits 0, 1 and 2. A same-length modification to signed synthetic material data produced a confirmed difference. An independently generated wrong public key yielded upstream exit 3 and inconclusive trust. A store with mismatched bytes or ambiguous latest receipts remained inconclusive. The policy retained a current or partial advisory match under incomplete coverage. Replaying the historic snapshot at a later clock showed it no longer met the specified age.

All three fixed collectors ran on synthetic inputs. The fresh bundled grid campaign completed 64 attempts. A disposable repository passed the full restic data check. The recovery plan identified the same snapshot; its destination stayed empty. The ordinary executed-restore sample was read from the upstream publication. The synthetic strict-digest pass is a constructed control. No restore or live advisory lookup ran in this project.

`python tools/robustness.py --seed 61 --count 120` exercised 360 bounded inputs. Policy produced 41 accepted and 79 rejected. Receipt produced 40 accepted and 80 rejected. Report produced 20 accepted, 20 incomplete and 80 rejected. No uncaught exception occurred.

The first collector integration run exposed a missing Windows home boundary in the sanitized child environment. Passing the required home path allowed signed verification to run while the synthetic secret environment marker stayed out of the child. Final review also added failure receipts for unsuccessful collection and regression coverage for discarded parser controls. A failed collection now prevents an older pass from clearing that check. The exact command list and the verified restic installation steps are in [CONTRIBUTING.md](../CONTRIBUTING.md) and [CI](../.github/workflows/ci.yml).

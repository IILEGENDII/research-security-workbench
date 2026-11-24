# Limits in v0.1.0

- Only the five listed revisions and six named operations have integration evidence. Unknown, malformed and conflicting evidence cannot clear a check.
- A workstation check requires a local capture. Operator imports and bundled synthetic tests carry weaker assurance. A real workstation requiring backup or restored-file equivalence stays incomplete. An independently authenticated signed digest baseline for ordinary recovery is future work.
- File equality is relative to the selected signed baseline and trusted public key. Baseline replay, a compromised signer, and an incomplete original baseline require external controls. A full pack read alone says nothing about omitted source files.
- Dependency assessment covers eligible PyPI identities in the declared inventory. Offline evidence remains locally editable. Native libraries, Conda packages, drivers, compilers, MPI and OS packages need separate coverage. Live OSV queries, automatic restores, scanners for external targets and automatic remediation are outside the workbench.
- The parser adapter refers only to its bundled target, seed controls and completed cases. The source scanner identifies patterns for review. Neither measures exploitability.
- A trusted clock is required. Local file and subprocess limits bound input, output and elapsed time. They provide no hard child memory or CPU quotas. A hostile child spawning unrelated descendants is outside the pinned-tool trust model. Windows process cleanup covers the launched process.
- A local filesystem must support the chosen private no-clobber publication operation. POSIX mode checks and Windows operator-managed ACLs have different coverage. Keep an independent copy of the policy and evidence. Files can change between observations.
- JSON and text are the supported report formats. Signatures, attestations, a web interface and unattended operation are outside this release.

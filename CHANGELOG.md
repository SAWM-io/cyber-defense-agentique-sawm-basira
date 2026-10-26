# Changes

## 0.2.0 - 2026-10-26

- Add a continuous, read-only defence-in-depth assessment with 12 OS probes and 10 runtime checks.
- Add a collapsible monochrome posture dashboard and bounded JSON export, with explicit unknown/stale evidence.
- Require a short-lived, administrator-enrolled Ed25519 authorization for modifying executor actions when the profile is enabled. Bind authorization to decision, target, expected process identity and manifest; retain all maintenance and action checks.
- Give SAWM the observed posture without granting new rights or claiming ISO certification.
- Document ISO 27001 / CIS alignment, deployment, institutional responsibilities and remaining validation.
- Complete the new-installation observation baseline without granting automatic actions.
- Provide a separate autonomous investigation example with predelegated actions, mandatory key enrollment and documented capacity limits.

## 0.1.1 - 2026-10-26

- Make Mac hypervisor tests independent of the CI host operating system.
- Verify Linux and local-VM host sampling does not invoke UTM or scan Mac QEMU processes.
- Show individual test failures in CI while retaining the private local test report.
- Run all three Python validation jobs even when one fails.

## 0.1.0 - 2026-10-24

Initial standalone client integration, extracted from the Salle des Machines lab.

- Public Basira / SAWM Cloud SDK and typed decision connector.
- Linux telemetry, scoped file/process/network observations and optional eBPF/LSM examples.
- Local policy enforcement, signed maintenance, bounded investigations and action verification.
- Dashboard with observations, decisions, effects and Cloud call accounting.
- Offline integration tests and separate-instance configuration tests.
- Customer documentation and an architecture illustration.
- Removed private deployment identifiers, historical evidence and workstation paths.
- Explicit SSH target with strict host-key checking; loopback defaults.
- Cloud and action execution are separate opt-ins; initial manifest allows no intervention.

This release is validated by local tests. It does not certify a customer's kernel,
Cloud subscription, firewall configuration or complete protection against malware.

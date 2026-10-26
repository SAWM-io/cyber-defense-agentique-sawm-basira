# Changes

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

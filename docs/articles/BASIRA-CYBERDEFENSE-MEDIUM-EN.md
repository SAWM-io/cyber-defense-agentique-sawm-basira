# Basira and SAWM: agentic cyber defense that observes, acts and verifies

[Français](BASIRA-CYBERDEFENSE-MEDIUM.md) | **English**

**How to give an agent a memory of incidents on your server and controlled ways to act, using the Basira and SAWM Cloud APIs.**

A database stops responding. A process starts consuming more resources. Connection attempts fail, then repeat. For the IT team, the challenge is to reconstruct the situation: who did what, was it authorized, which action will preserve the service, and how can we verify that it worked?

With **SAWM and Basira**, we are developing a cyber defense loop that connects these steps. Sensors observe the server. Memory retains events and the results of interventions. The agent retrieves context, can request additional checks, and then proposes an action within the organization's delegated authority. A local executor checks that authorization and verifies the outcome.

The **Cyber Defense Agentique SAWM&Basira** kit is available on [GitHub](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira). It uses the real Cloud APIs. It enables a team to build a Linux demonstrator and then assess the defensive coverage of its own deployment.

![SAWM and Basira agentic cyber defense architecture](../assets/architecture.png)

*The kit connects sensors, memory, investigation, local authorization and verification. In the test campaign described here, the sensors and executor run inside a Linux VM; the controller and dashboard run on the host.*

## Memory that preserves incident context

The same symptom can have several explanations. Heavy disk activity may come from a legitimate backup. A changed hash may result from authorized maintenance. A database lock may be temporary or make the service unavailable.

Basira makes observations and feedback from previous interventions available to the next investigation. The agent can retrieve what was reported, the decision taken and the reported outcome, within the scope its service principal is allowed to access.

The four components have distinct roles:

- **Basira** retains events and their provenance.
- **TSST** retrieves relevant evidence from the memory the principal is authorized to access.
- **ODVL** helps rank the retrieved items. It adds no evidence and grants no permissions.
- **SAWM** examines the context, selects inspections or proposes an intervention, and provides a public rationale.

An old observation remains an old observation. Before intervening, the system must check the server's current state. Memory and sensors complement each other.

## An intervention that actually ran

On October 26, 2026, we tested this chain in a Linux VM, using a test SQLite database and the real Cloud APIs.

A process held an exclusive lock that prevented database operations. The investigation linked the lock to the relevant service unit, checked permissions, and sent the evidence to SAWM.

SAWM chose to **stop the responsible service**. A signed ticket bound that proposal to a specific target and action. The local executor rechecked the delegated authority and target identity before acting. After the stop, reads and writes were restored, the control service remained available, and the outcome was recorded in Basira.

The demonstrated result is concrete: **an observation led to a SAWM decision, followed by an authorized action whose effect was checked**. This was not a text response pretending to stop a service. The [campaign evidence](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira/blob/main/docs/VALIDATION-VM-2026-10-26.md) also documents local tests, incidents encountered and limitations.

## Autonomy defined by the server owner

The agent can intervene without requesting confirmation for every incident when that intervention has been delegated in advance. The owner defines the permitted units, files and actions, protected resources, and maintenance authorizations.

A SAWM proposal alone cannot execute a command. The controller and executor check, among other things, the authorizing authority, evidence freshness, target identity, ongoing maintenance and the signed ticket's validity. The model is not given an unrestricted root shell.

This separation matters: a filename or log entry containing an instruction remains data to examine. It cannot change the agent's authority.

Local guards also have limited delegated authority for specific cases, including when the Cloud is unavailable. The dashboard distinguishes their interventions from decisions made by SAWM.

## What the demonstrator already lets you verify

The campaign includes several complementary mechanisms:

- **Database availability:** attributing a lock and performing a targeted stop, with read and write checks after intervention.
- **File or database integrity:** detecting a discrepancy and locally containing the process identified as responsible. Restoring data remains a separate operation.
- **Authorized maintenance:** verifying a signed maintenance authorization and refusing an incompatible intervention.
- **Repeated authentication failures:** on the demonstration service, five incorrect passwords led to a temporary block of the source; expiration and restored access were verified.
- **SSH observation:** rejected connections produced an alert while preserving legitimate access. This probe does not automatically block SSH access.
- **Kernel protection:** a BPF LSM policy denied a test-file read to the targeted process, including when running as root, while preserving an authorized control read.

The repository also includes modules for inspecting resources, connections, explicitly submitted `.deb` packages with ClamAV, and large files. Their validation depends on the scenario and target server. A CPU spike alone is not proof of malware.

One aspect of SAWM's decision-making still needs improvement: in a protected maintenance case, the agent requested additional clarification. It did not stop the process, but the full-autonomy criterion for that test was not met.

## Connecting your server to the Cloud APIs

### 1. Create access for your environment

In [your Basira workspace](https://basira.sawm.io/espace), use an authorized account to create a memory space, an entity representing the server, and a dedicated service principal.

Grant that principal `read` and `write` permissions on the relevant entity. Then issue a key using the **Runtime agent + SAWM** profile, with these scopes:

```text
events:write jobs:read memory:recall tsst:recall odvl:rank sawm:run
```

API scopes and entity permissions are separate checks. A key should not receive global access to every dossier merely to observe one server.

### 2. Install and test the connector

On your control workstation, with Python 3.11 or later, Git, and Node.js for the interface tests:

```bash
git clone https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira.git
cd cyber-defense-agentique-sawm-basira
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
mkdir -p releves/rapports releves/series
python tests/run_safe.py
```

This suite checks the software without making Cloud calls or acting on your server.

### 3. Configure the private credential file

```bash
mkdir -p "$HOME/.sawm-labo"
chmod 700 "$HOME/.sawm-labo"
cp .env.example "$HOME/.sawm-labo/env"
chmod 600 "$HOME/.sawm-labo/env"
```

Fill in this file in your editor with your own identifiers:

```dotenv
BASIRA_BASE=https://basira-api.sawm.io/api/v1/basira
BASIRA_SPACE=mem_REPLACE_WITH_YOUR_SPACE
BASIRA_ENTITY=ent_REPLACE_WITH_YOUR_ENTITY
BASIRA_PRINCIPAL=prn_REPLACE_WITH_YOUR_PRINCIPAL
BASIRA_KEY=REPLACE_WITH_YOUR_PRIVATE_SERVICE_KEY
```

The connector reads this file directly. Keep it out of the repository and screenshots. Service keys must remain revocable and specific to the environment.

Here is a first real memory recall, to run from the repository root using its Python environment. The SDK identifiers remain unchanged:

```python
from uuid import uuid4
from connecteur.pont_memoire import PontMemoire

bridge = PontMemoire(coffre="~/.sawm-labo/env", campagne=uuid4().hex)
try:
    recall = bridge.rappeler(
        "Which availability incidents have been observed?",
        limite=5,
    )
    print({"evidence": recall.nombre, "engine": recall.moteur})
finally:
    bridge.close()
```

This recall uses events already present in your entity and does not act on the server. Cloud calls may consume credits; an empty memory should not be mistaken for an unavailable engine.

### 4. Install the sensors and connect Linux

The kit relies on systemd, cgroup v2, `/proc`, journald and networking tools. The eBPF and BPF LSM probes require a compatible kernel. **SAWM and Basira are not installed in the kernel: the probes and local protections operate there.**

The [quickstart guide](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira/blob/main/docs/QUICKSTART.md) explains how to prepare a dedicated VM, systemd units, transport, SSH keys and freshness checks. The provisioning tool refuses an existing installation and does not automatically compile the advanced probes.

You can host the controller inside the VM or on a separate host. In the latter case, configure an explicit SSH target, its verified host key, and private or authenticated telemetry transport. The dashboard stays on loopback and can be accessed remotely through an authenticated tunnel. Monitoring commands assume these connections are already configured.

### 5. Move from observation to action

On the configured controller, start the collector in a first terminal:

```bash
python controleur/collecteur.py
```

Open `http://127.0.0.1:8899/`. In a second terminal using the same Python environment, start with observation:

```bash
python controleur/veille.py --duration 60
```

Then add Cloud analysis without automatic intervention:

```bash
python controleur/veille.py --duration 300 --cloud --cloud-per-hour 4
```

Once you have validated the manifest, enrolled the keys and delegated actions on your test targets, enable continuous monitoring:

```bash
python controleur/veille.py --permanent --cloud --apply --cloud-per-hour 4
```

The `--apply` flag does not bypass any authorization. The profile requires the configured signatures and local checks. The budget is persistent: four SAWM turns per hour in this example, not four HTTP requests. For a controller running locally inside Linux, the guide provides the `SAWM_LABO_LOCAL_VM=1` prefix, execution account and paths to use. Cloud analysis still uses the Cloud APIs.

## What your team sees in the dashboard

The interface brings together server health, sensor freshness, incidents, decisions, execution receipts and verified effects. Collapsible cards let you examine an event without losing the overall view.

Basira and SAWM Cloud calls are visible with their statuses, latencies and attempts. Usage figures appear when the API provides them. The recent campaign distinguishes SAWM decisions, local guards, successful tests and those that still require a correction.

For the security lead, the goal is to answer a precise question: **what did we observe, why was this intervention authorized, and what outcome did we actually verify?**

## Defense in depth and security frameworks

The project combines delegated authority, timestamped observations, inspections, Ed25519 tickets, local checks and logging. This defense in depth provides evidence that can support a security program.

The [client report](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira/blob/main/docs/rapports/SAWM-Basira-Cyberdefense-Agentique-2026-10-26.pdf) describes possible contributions to [ISO/IEC 27001](https://www.iso.org/standard/27001) initiatives, the [CIS Controls](https://www.cisecurity.org/controls/cis-controls-list), and the [MITRE D3FEND](https://d3fend.mitre.org/faq/) vocabulary. These mappings do not constitute ISO certification or a guarantee of universal protection.

The public kit is licensed under Apache 2.0, with a BPF LSM component under GPL-2.0-only. The SAWM, Basira, TSST and ODVL engines remain proprietary and are accessed through Cloud services. Define the scope of transmitted data, retention, model providers and residency requirements before a business deployment.

## Building a verifiable defense pilot

A useful pilot starts with a few representative services: a database to preserve, maintenance to respect, connections to observe, and a control service to keep available. The criteria cover correct decisions, false positives, response times, effects and recovery after a failure.

SAWM and Basira aim to give defense continuity: preserve context, act within explicit delegated authority, and reuse observed outcomes in subsequent investigations.

**Explore the [public repository](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira), read the [Cloud guide](https://github.com/SAWM-io/cyber-defense-agentique-sawm-basira/blob/main/docs/CLOUD.md), and prepare your environment in the [Basira workspace](https://basira.sawm.io/espace).**

*This is the English edition of the article. The linked detailed guides, campaign evidence, PDF report and architecture illustration are currently in French; the executable identifiers and commands are shared by both editions.*

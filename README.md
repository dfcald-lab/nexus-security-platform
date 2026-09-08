# NEXUS

### Network EXploration, Unified eXposure & Security Intelligence

> **A local-first cybersecurity observability and operator platform that turns raw network and host observations into state, incidents, intelligence, validation plans, and actionable evidence.**

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Jetson-111827)](https://github.com/dfcald-lab/nexus-security-platform)
[![Language](https://img.shields.io/badge/Language-Python%203-3776AB)](https://www.python.org/)
[![AI](https://img.shields.io/badge/AI-Local%20Ollama-111827)](https://ollama.com/)
[![Security](https://img.shields.io/badge/Security-Evidence--Driven-0F766E)](https://github.com/dfcald-lab/nexus-security-platform)
[![Status](https://img.shields.io/badge/Status-Active%20Development-F59E0B)](https://github.com/dfcald-lab/nexus-security-platform/commits/main/)

---

## ⚡ What is NEXUS?

NEXUS started as a network-monitoring project and evolved into a small security platform built around a simple rule:

> **Deterministic systems establish what happened. AI helps interpret it. Evidence decides what is supported. Humans stay in control.**

Instead of treating monitoring, AI, security validation, and lab research as separate projects, NEXUS connects them into one local-first workflow.

```text
                           NEXUS
                             │
             ┌───────────────┴───────────────┐
             │                               │
        NETWORK / HOST                   OPERATOR LAB
          OBSERVATIONS                  HTB / RESEARCH
             │                               │
             ▼                               ▼
      COLLECTION + PARSING             SERVICE INVENTORY
             │                               │
             ▼                               ▼
        STATE + DIFF                    CVE RESEARCH
             │                               │
             ▼                               ▼
      EVENT LIFECYCLE                  EVIDENCE MODEL
             │                               │
             └───────────────┬───────────────┘
                             ▼
                    NEXUS INTELLIGENCE
                      /             \
                     /               \
                    ▼                 ▼
               BLUE AI           RED TEAM AI
              ADVISORY          VALIDATION PLAN
                    \                 /
                     \               /
                      └──────┬──────┘
                             ▼
                       HUMAN OPERATOR
                             │
                 ┌───────────┼───────────┐
                 ▼           ▼           ▼
             DASHBOARD     OLED        CUBE LED
                                         + AUDIO
```

---

## 🧠 The Core Design Decision

NEXUS deliberately separates **observation**, **interpretation**, and **action**.

### Deterministic monitoring is authoritative

Switch output, parsed state, topology changes, device history, thermal telemetry, and event lifecycle logic are handled deterministically.

### AI is advisory

The Blue AI layer receives NEXUS evidence and produces structured interpretation. It does not create the underlying network truth.

### Security validation is bounded

The Red Team layer generates structured, non-destructive validation plans rather than autonomously attacking systems.

### Evidence remains explicit

Prerequisites can be tracked as:

```text
✓ VERIFIED
✗ CONTRADICTED
? UNKNOWN
```

That lets NEXUS distinguish:

```text
"This version is affected"

from

"The conditions required for this vulnerability are supported by evidence"

from

"The exploit was actually demonstrated"
```

Those are three different claims.

---

# 🔥 Feature Overview

| Subsystem | What it does |
|---|---|
| 📡 Network Collection | Collects switch version, interfaces, VLANs, routes, MAC tables, ARP, CDP, spanning tree, and interface health data. |
| 🧩 Parsing & State | Converts raw device output into structured state and persistent records. |
| 🧭 Device Identity | Resolves recurring devices and tracks historical device/port relationships. |
| 🔎 Change Detection | Detects changes in devices, ports, MAC relationships, network state, and topology. |
| 🚨 Event Lifecycle | Creates, classifies, activates, correlates, and resolves events. |
| 🧠 Intelligence | Correlates related events into higher-level situations with risk and context. |
| 🤖 Blue AI | Local LLM advisory interpretation with structured output and evidence guardrails. |
| 🔴 Red Team AI | Structured, bounded security validation planning. |
| 🧪 Safe Simulator | Generates controlled synthetic events for pipeline testing. |
| 🌡️ Thermal Telemetry | Tracks Jetson CPU/GPU/TJ thermal state and system metrics. |
| 💡 Hardware Alerts | Maps severity to OLED, CUBE LEDs, and short critical audio alerts. |
| 🧪 HTB Operator | Separate operator workspace for authorized labs and Hack The Box research. |
| 🔍 CVE Research | Matches discovered versions against NVD data and records public exploit references. |
| ✅ Evidence Tracking | Tracks vulnerability prerequisites condition-by-condition. |
| 📊 Dashboard | Central browser interface for current state, intelligence, hardware, incidents, and HTB research. |

---

# 🏗️ Architecture

A normal NEXUS monitoring cycle follows a deterministic pipeline:

```text
Switch collection
       ↓
Structured parsing
       ↓
Device identity resolution
       ↓
State comparison
       ↓
Topology construction
       ↓
Topology comparison
       ↓
Thermal / host telemetry
       ↓
Event classification + lifecycle
       ↓
Published Jetson state
       ↓
NEXUS intelligence correlation
       ↓
Blue AI / Red Team advisory processing
       ↓
Dashboard + physical alerting
```

The project is intentionally split into cooperating layers rather than one autonomous security agent.

### Source tree

```text
nexus/
├── dashboard/
│   ├── nexus_dashboard.py
│   └── static/
│       └── nexus.js
│
├── hardware/
│   ├── nexus_hardware.py
│   └── nexus_led.py
│
├── oled/
│   └── nexus_oled.py
│
├── scripts/
│   ├── nexus_monitor.py
│   ├── monitor_switch.sh
│   ├── agent/
│   │   ├── switch_info.py
│   │   ├── switch_parser.py
│   │   ├── device_identity.py
│   │   ├── device_history.py
│   │   ├── device_state.py
│   │   ├── network_info.py
│   │   ├── network_models.py
│   │   ├── network_topology.py
│   │   ├── topology_diff.py
│   │   ├── switch_diff.py
│   │   ├── event_classifier.py
│   │   ├── event_history.py
│   │   ├── event_state.py
│   │   ├── event_alert.py
│   │   ├── nexus_intelligence.py
│   │   ├── nexus_ai.py
│   │   ├── nexus_redteam.py
│   │   ├── nexus_simulate.py
│   │   ├── telemetry_state.py
│   │   └── publish_jetson_state.py
│   │
│   └── operator/
│       ├── nexus_operator.py
│       ├── htb_session.py
│       └── htb/
│           ├── service_parser.py
│           └── research.py
│
└── systemd/
    └── nexus-monitor.service
```

---

# 📡 Network Intelligence

NEXUS collects and reasons over structured switch observations instead of simply displaying command output.

The network collector gathers data including:

- Cisco IOS/platform information
- interface state and descriptions
- interface error counters
- switchport state
- VLAN state
- routing information
- dynamic MAC addresses
- ARP mappings
- CDP neighbors
- spanning-tree state

The parser layer turns that output into machine-readable records. The state/diff layers then compare observations across cycles.

This makes a change like:

```text
MAC appears on Fa4/0/1
```

more useful than a raw log line because NEXUS can ask:

```text
Was this device already known?
Was the relationship changed?
Has the device moved before?
Is the event new or recurring?
Does another observation explain it?
```

---

# 🧭 Persistent Device Identity

NEXUS keeps historical device relationships so the same observed device can be tracked across monitoring cycles.

The system can distinguish concepts such as:

```text
NEW DEVICE
DEVICE RETURNED
DEVICE MOVED
MAC ADDED
MAC REMOVED
PORT RELATIONSHIP CHANGED
```

That historical context feeds the intelligence layer rather than being discarded after each monitoring cycle.

---

# 🚨 Event Lifecycle

NEXUS treats an event as a lifecycle, not an endless stream of duplicate alerts.

```text
OBSERVED
   ↓
CLASSIFIED
   ↓
ACTIVE
   ├───────────────┐
   │               │
   ▼               ▼
CORRELATED      RECURRENT
   │
   ▼
RESOLVED
```

The same model is used for network conditions and supported hardware/thermal incidents.

A thermal transition such as:

```text
NORMAL → HIGH
```

can create an active incident, while a matching recovery:

```text
HIGH → NORMAL
```

can resolve it.

---

# 🌡️ Hardware & Thermal Telemetry

NEXUS can monitor Jetson thermal zones and system health alongside network observations.

Tracked telemetry includes:

- CPU temperature
- GPU temperature
- Jetson TJ temperature
- available SoC thermal data
- CPU utilization
- RAM utilization

Thermal state is classified deterministically:

```text
UNKNOWN
NORMAL
ELEVATED
HIGH
CRITICAL
```

Thermal incidents can then enter the same lifecycle and intelligence pipeline as network events.

---

# 🧠 NEXUS Intelligence

The intelligence layer converts multiple observations into higher-level situations.

A situation can contain:

```text
subject
source event type
number of events
highest score
risk
confidence
explanation
investigation guidance
supporting metrics
```

An important design choice is **correlation without double counting**.

For example, multiple sensors contributing to a single thermal incident can be grouped into one logical incident while retaining the individual contributing sensors as evidence.

---

# 🤖 Blue AI

NEXUS includes a local AI advisory layer backed by Ollama.

The AI pipeline is intentionally constrained:

```text
NEXUS deterministic evidence
          ↓
structured prompt
          ↓
local LLM
          ↓
structured response
          ↓
validation
          ↓
advisory result
```

The response contract distinguishes:

```text
OBSERVED
POSSIBLE
UNDETERMINED
```

and tracks fields such as:

- interpretation
- confidence
- recommended action
- reasoning summary
- evidence status

Unsupported security conclusions can be rejected by validation rather than blindly displayed as truth.

### Local-first AI

The repository expects Ollama to remain local to the host. The AI layer is not intended to ship monitoring data to a remote inference service.

---

# 🔴 Red Team AI

The Red Team component is a **validation planner**, not an autonomous attacker.

Its structured output includes:

```text
Target
Attack surface
Objective
Hypothesis
Priority
Validation plan
Expected evidence
Safety note
```

The validator explicitly blocks categories including:

- denial-of-service actions
- credential theft
- password spraying
- persistence
- backdoors
- destructive payload execution
- data exfiltration
- evasion
- disabling logging

The intended workflow is:

```text
Observed situation
       ↓
Red Team hypothesis
       ↓
Safe validation plan
       ↓
Human operator review
       ↓
Authorized testing
       ↓
Evidence
```

---

# 🧪 Safe Simulation

NEXUS includes a controlled simulator for testing the monitoring pipeline without relying on a live network change.

It can exercise the same kinds of downstream logic used by production monitoring:

```text
Synthetic event
      ↓
State / lifecycle processing
      ↓
Alert generation
      ↓
Intelligence correlation
      ↓
Published state
```

This provides a repeatable way to verify lifecycle and correlation behavior.

---

# 🧪 HTB Operator

The HTB subsystem is intentionally separate from automatic monitoring.

```text
NEXUS Monitor
    = automatic + deterministic

Blue AI
    = automatic + advisory

Red Team AI
    = automatic + bounded validation planning

HTB Operator
    = conversational + human-directed research
```

The operator workspace can maintain:

- target information
- discovered services
- versions
- findings
- notes
- evidence
- CVE research
- public exploit references

### Service inventory

Example workflow:

```text
Nmap output
    ↓
Service parser
    ↓
Service / version inventory
    ↓
Research
```

The service parser keeps port, protocol, service, version, and raw evidence together so later research has a traceable source.

---

# 🔎 CVE Research & Evidence

The research subsystem uses public NVD CVE data and records public Exploit-DB references.

Research records can contain:

```text
CVE
CVSS
Version status
Requirement
Platform
Conditions
Evidence assessment
Exploitability status
Exploitability reasoning
NVD reference
Exploit-DB references
```

### Example evidence-driven state

```text
CVE-2025-24813

VERSION
AFFECTED

EXPLOITABILITY
UNCONFIRMED

CONDITIONS
? default servlet write enabled
✓ partial PUT support
? file-based session persistence

1/3 VERIFIED · 2 UNKNOWN

EXPLOIT REFERENCE
EDB-52134
```

The distinction is deliberate:

```text
VERSION MATCH
    ≠
EXPLOITABILITY
    ≠
SUCCESSFUL EXPLOITATION
```

The dashboard can also derive a conservative condition state:

```text
UNCONFIRMED
PARTIALLY VERIFIED
CONDITIONS SATISFIED
BLOCKED
```

Those states represent prerequisite evidence. They do not claim that an exploit succeeded.

---

# 📊 Dashboard

The dashboard is the primary operator-facing interface and brings the platform layers together.

Current dashboard areas include:

```text
CURRENT STATE
├── system status
├── risk / severity
├── active events
└── devices / topology

INTELLIGENCE
├── situations
├── metrics
├── Blue AI
└── Red Team

HARDWARE
├── OLED / LED / audio health
└── thermal telemetry

HTB LAB
├── services
├── versions
├── CVEs
├── conditions
├── evidence
├── exploit references
└── operator workspace
```

The interface is designed for local browser access and mobile-friendly operation in the lab.

---

# 💡 Physical Alerting

NEXUS connects software severity to physical feedback.

```text
                   NEXUS SEVERITY
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
            OLED        LED       AUDIO
             │           │           │
          details     persistent   short
          / alerts    severity     critical
```

The hardware layer is designed so critical conditions can be visible on the Jetson itself while important alerts can also produce a short audible notification.

The audio path is intentionally event-driven rather than a constant alarm.

---

# 🔐 Security Model

NEXUS is built as a local-first lab platform.

### Secrets stay outside source code

Sensitive credentials are expected to come from environment configuration rather than hard-coded source values.

### AI stays local

The intended AI path uses local Ollama inference.

### Evidence precedes interpretation

Deterministic monitoring produces the evidence consumed by downstream intelligence.

### Human remains in the loop

The operator decides what authorized security validation to execute.

### Runtime data stays out of the public repository

Live monitoring state, credentials, HTB session data, logs, and hardware runtime files are environment-specific and should remain local.

---

# 🚀 Getting Started

NEXUS is an active engineering project and is currently optimized for a Linux/Jetson lab environment.

The public repository is intended to document the architecture and provide the implementation. Deployment is still being generalized for other environments.

### Clone

```bash
git clone git@github.com:dfcald-lab/nexus-security-platform.git
cd nexus-security-platform
```

### Python environment

Use a Python 3 environment appropriate for your host and install the runtime packages required by the modules you enable.

The project currently includes components built around libraries such as:

- `pexpect`
- `psutil`
- `Pillow`
- `luma.core`
- `luma.oled`

Hardware-specific deployments additionally require the appropriate Yahboom CUBE driver stack.

### Local configuration

Environment variables are used for deployment-specific values such as:

```text
NEXUS_SWITCH_PASSWORD
NEXUS_JETSON_HOST
NEXUS_CUBENANO_DRIVER
NEXUS_TELEMETRY_FILE
NEXUS_INTELLIGENCE_DIR
```

Do not commit real credentials or live environment data.

---

# 🧪 Development & Validation

NEXUS is developed iteratively with small, inspectable changes rather than one large generated code drop.

Validation has included:

```text
Python syntax checks
isolated event simulation
thermal lifecycle simulation
publisher lifecycle testing
alert aggregation testing
AI validation tests
Red Team output validation
HTB parser tests
CVE research tests
live dashboard checks
hardware output checks
```

The public repository intentionally preserves the development history so the implementation can be reviewed commit-by-commit.

---

# 📈 Project Evolution

The public history shows the system growing in layers:

```text
Continuous Monitoring
        ↓
State + Device Identity
        ↓
Event Classification
        ↓
Hardware Alerts
        ↓
Structured Intelligence
        ↓
Local AI
        ↓
AI Validation + Freshness
        ↓
Safe Simulation
        ↓
HTB Operator
        ↓
CVE Research
        ↓
Condition Evidence
        ↓
Deterministic Exploitability
```

This is intentionally preserved in Git rather than squashed into one release commit.

---

# 🛣️ Roadmap

The project is still evolving.

Planned engineering areas include:

- [ ] Portable systemd installation
- [ ] More modular dashboard architecture
- [ ] Expanded automated test suite
- [ ] More hardware abstraction
- [ ] Better deployment configuration templates
- [ ] Additional network device support
- [ ] Richer incident visualizations
- [ ] More detailed HTB research workflows
- [ ] Public-safe screenshots and demonstrations

---

# ⚠️ Scope & Safety

NEXUS is intended for **authorized environments**, personal labs, owned infrastructure, and controlled training platforms such as Hack The Box.

The HTB and Red Team components are designed around human-directed, bounded, non-destructive validation. Public vulnerability references are stored as research metadata; NEXUS does not automatically execute arbitrary public exploit code.

Always obtain authorization before testing systems you do not own or administer.

---

# 👤 Author

**Dorian Calderon**

Cybersecurity-focused software engineering project centered on Linux, Python, network monitoring, security automation, local AI, and hands-on infrastructure.

Built as an evolving lab platform rather than a static demo.

---

# 📜 License

License and redistribution terms are still being finalized for the public release.

---

## ⭐ Why NEXUS?

Most monitoring demos stop at:

```text
Something changed.
```

NEXUS is trying to answer the harder questions:

```text
What changed?

Is it actually new?

Has it happened before?

What evidence supports the conclusion?

What conditions still need verification?

What does the AI think—and can that interpretation be trusted?

How should a human operator validate it safely?

What should the system display locally?
```

That progression—from **raw observation → state → event → intelligence → evidence → human-directed action**—is the core idea behind NEXUS.

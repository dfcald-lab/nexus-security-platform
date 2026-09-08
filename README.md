# NEXUS

### Network EXploration, Unified eXposure & Security Intelligence

> **A local-first cybersecurity observability and operator platform for network monitoring, evidence-driven intelligence, security validation, and authorized HTB research.**

NEXUS started as a network-monitoring project and has grown into a small security platform built around one core idea:

**collect evidence deterministically, preserve state, correlate what happened, and use AI as an advisor—not as the source of truth.**

It is designed to run on a Linux/Jetson-based lab environment, monitor network infrastructure, surface changes and incidents, correlate hardware telemetry, provide structured AI analysis, and give a human operator a separate workspace for authorized security research.

---

## ⚡ What NEXUS Does

| Layer | Purpose |
|---|---|
| 📡 **Network Collection** | Collects switch state, interfaces, VLANs, routes, MAC tables, ARP, CDP, spanning tree, and interface health data. |
| 🧩 **Parsing & State** | Converts device output into structured records and tracks persistent device identity, state, and relationships. |
| 🔎 **Change Detection** | Compares current and previous observations to identify network, topology, and device changes. |
| 🚨 **Event Lifecycle** | Creates, classifies, correlates, tracks, and resolves events instead of treating every observation as a new incident. |
| 🧠 **NEXUS Intelligence** | Groups related events into higher-level situations and produces deterministic risk/context summaries. |
| 🤖 **Blue AI** | Uses a local LLM for structured advisory interpretation while deterministic monitoring remains authoritative. |
| 🔴 **Red Team AI** | Generates bounded, non-destructive validation plans for observed situations. |
| 🧪 **HTB Operator** | Provides a separate conversational workspace for authorized Hack The Box/lab research. |
| 🛡️ **CVE Research** | Matches discovered software versions against NVD data and tracks exploit references from Exploit-DB. |
| ✅ **Evidence Tracking** | Records condition-by-condition evidence as VERIFIED, CONTRADICTED, or UNKNOWN. |
| 🌡️ **Hardware Telemetry** | Tracks Jetson CPU/GPU/TJ thermal state and system health. |
| 💡 **Physical Alerting** | Integrates OLED, CUBE LEDs, and short critical audio alerts with NEXUS severity. |
| 📊 **Web Dashboard** | Presents current state, incidents, intelligence, AI status, hardware health, network topology, and HTB research. |
| 🧪 **Safe Simulation** | Provides controlled synthetic event generation for testing the event pipeline without touching production state. |

---

## 🧠 Design Philosophy

NEXUS intentionally separates **facts, interpretation, and action**.

```text
                    ┌─────────────────────┐
                    │   Network / Host    │
                    │      Evidence       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Deterministic       │
                    │ Collection + Parsing │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ State + Diff +      │
                    │ Event Lifecycle     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ NEXUS Intelligence  │
                    │ Correlation Layer   │
                    └───────┬─────┬───────┘
                            │     │
                 ┌──────────┘     └──────────┐
                 ▼                           ▼
        ┌─────────────────┐        ┌─────────────────┐
        │    Blue AI      │        │   Red Team AI   │
        │ Advisory Only   │        │ Validation Plan │
        └────────┬────────┘        └────────┬────────┘
                 │                           │
                 └────────────┬──────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ Human Operator      │
                    │ + HTB Research     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Dashboard / OLED /  │
                    │ LED / Audio         │
                    └─────────────────────┘
```

### The most important rule

**AI does not create network truth.**

The monitoring pipeline determines what was observed. AI receives that evidence and produces structured interpretation. Validation logic rejects unsupported conclusions. The human operator remains in control of security actions.

---

# 🏗️ Architecture

NEXUS is organized around several cooperating layers rather than one giant monitor script.

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
│   │
│   ├── agent/
│   │   ├── switch_info.py
│   │   ├── switch_parser.py
│   │   ├── device_identity.py
│   │   ├── device_history.py
│   │   ├── device_state.py
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

# 📡 Network Monitoring Pipeline

A normal monitoring cycle follows a deterministic sequence:

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
Telemetry assessment
      ↓
Event lifecycle
      ↓
Jetson state publication
      ↓
NEXUS intelligence correlation
      ↓
Blue AI / Red Team advisory processing
```

The switch collector uses SSH automation through `pexpect` and gathers information such as:

- IOS version and platform information
- interface state
- interface descriptions
- interface error counters
- switchport configuration
- VLAN state
- routing information
- dynamic MAC addresses
- ARP mappings
- CDP neighbors
- spanning-tree state

The collector is intentionally evidence-oriented: raw device output is transformed into structured state before higher-level reasoning occurs.

---

# 🧩 Device Identity & History

NEXUS does not treat a MAC address appearing on a different observation cycle as an entirely new device.

The device layer maintains persistent identity and historical relationships so the system can distinguish changes such as:

```text
NEW DEVICE
DEVICE RETURNED
DEVICE MOVED
MAC ADDED
MAC REMOVED
PORT RELATIONSHIP CHANGED
```

This historical context becomes important when intelligence evaluates recurring network behavior rather than isolated observations.

---

# 🚨 Event Lifecycle

NEXUS uses an event lifecycle instead of simply appending alerts forever.

Conceptually:

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

Events retain historical context while the current state focuses on actionable incidents.

Thermal incidents use the same lifecycle model. A condition moving from `NORMAL → HIGH` can create an active thermal incident, while a matching `HIGH → NORMAL` recovery can resolve it.

---

# 🧠 NEXUS Intelligence

The intelligence layer converts individual events into higher-level situations.

For example, multiple thermal events affecting the same Jetson sensor group can be represented as one logical situation rather than several independent incidents.

Likewise, network observations can be grouped into situations that provide:

- subject
- event count
- highest observed score
- risk level
- confidence
- explanation
- investigation guidance
- supporting metrics

The important design choice is that correlation is **deterministic and inspectable**.

---

# 🤖 Blue AI

NEXUS includes a local AI advisory layer backed by Ollama.

The AI client is deliberately constrained to a local Ollama endpoint and uses structured output. The model does not replace the monitoring engine.

The AI contract distinguishes:

```text
OBSERVED
POSSIBLE
UNDETERMINED
```

and validates returned fields such as:

- interpretation
- confidence
- recommended action
- reasoning summary
- evidence status

The validation layer can reject responses that introduce unsupported conclusions.

### Why this matters

A security monitoring system should not turn an ambiguous observation into a confident incident simply because an LLM produced a convincing sentence.

NEXUS treats the LLM as **advisory intelligence over deterministic evidence**.

---

# 🔴 Red Team AI

The Red Team component is designed for defensive validation planning rather than autonomous exploitation.

It produces structured output such as:

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

The validator blocks categories such as:

- denial-of-service actions
- credential theft
- password spraying
- persistence
- backdoors
- destructive payloads
- exfiltration
- evasion
- disabling logging

The operator remains responsible for executing authorized validation steps.

---

# 🧪 HTB Operator Workspace

NEXUS also contains a separate operator workflow for **authorized labs and Hack The Box environments**.

The HTB subsystem can maintain:

- target information
- discovered services
- service versions
- findings
- notes
- evidence records
- vulnerability research
- Exploit-DB references
- CVE condition assessments

Example session flow:

```text
Nmap output
    ↓
Service parser
    ↓
Service/version inventory
    ↓
NVD research
    ↓
Version applicability
    ↓
Configuration conditions
    ↓
Evidence collection
    ↓
Exploitability state
```

The system intentionally separates **version applicability** from **exploitability**.

A matching CVE does not automatically mean the target is exploitable.

---

# 🔎 CVE & Exploit Research

The HTB research layer uses NVD CVE data and can correlate results with public Exploit-DB references.

Research records retain information such as:

```text
CVE
Version status
Exploitability status
Requirement
Platform
Conditions
Evidence assessment
Exploitability reasoning
Description
CVSS
NVD reference
Exploit-DB references
```

This enables condition-aware results such as:

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

That distinction is intentional: **the evidence layer can say what has been established without pretending that exploitation has already been demonstrated.**

---

# ✅ Evidence Model

Condition evidence uses three deterministic states:

```text
✓ VERIFIED
✗ CONTRADICTED
? UNKNOWN
```

This gives the operator an explicit answer to:

> “What do we actually know about this prerequisite?”

rather than relying on a free-form AI explanation.

Exploitability can then progress conservatively:

```text
UNCONFIRMED
      ↓
PARTIALLY VERIFIED
      ↓
CONDITIONS SATISFIED
```

A contradicted prerequisite produces:

```text
BLOCKED
```

None of these states claim that an exploit succeeded.

---

# 🌡️ Jetson Hardware Telemetry

NEXUS can monitor Jetson thermal state through Linux thermal-zone data and system metrics.

Tracked telemetry includes:

- CPU temperature
- GPU temperature
- Jetson TJ temperature
- SoC temperature data where available
- CPU utilization
- RAM utilization

Thermal conditions are classified deterministically into states such as:

```text
UNKNOWN
NORMAL
ELEVATED
HIGH
CRITICAL
```

Thermal state changes can enter the same event/intelligence pipeline as network events.

---

# 💡 Physical Alerting

The NEXUS hardware layer connects software severity to physical feedback.

```text
Severity
   ↓
OLED
LED
Audio
```

The current hardware design uses:

- **OLED** for status and alert display
- **CUBE LEDs** for severity visualization
- **short audio notification** for important/critical conditions

The audio path is intentionally not a constant alarm. It is used for significant events while the dashboard and physical LEDs remain available for persistent status.

---

# 🧪 Safe Event Simulation

NEXUS includes a simulator for controlled testing of event processing.

The simulator is designed to exercise the event pipeline without modifying production monitoring state.

This is useful for testing:

- event creation
- event classification
- state transitions
- resolution behavior
- publisher output
- alert generation
- intelligence correlation

Example concept:

```text
Synthetic event
      ↓
Normal NEXUS pipeline
      ↓
Observe resulting state
      ↓
Verify lifecycle behavior
```

---

# 🌐 Dashboard

The web dashboard is the main operator-facing view.

It brings together:

```text
┌──────────────────────────────────────┐
│              NEXUS                  │
├──────────────────────────────────────┤
│ Current System State                 │
│ Risk / Severity                     │
│ Active Events                       │
│ Device / Topology Information       │
│ Intelligence                        │
│ Blue AI status                      │
│ Red Team status                     │
│ Hardware health                     │
├──────────────────────────────────────┤
│ HTB LAB                             │
│  Services                           │
│  Versions                           │
│  CVEs                               │
│  Evidence                           │
│  Exploit references                 │
│  Operator workspace                 │
└──────────────────────────────────────┘
```

The dashboard also exposes the HTB operator workflow so research can be performed from the same local NEXUS environment.

---

# 🔐 Security Model

NEXUS is intentionally designed around a local-first security model.

### Local AI

The AI service is expected to run locally through Ollama rather than sending monitoring data to a remote hosted inference endpoint.

### Environment-based secrets

Sensitive values such as switch credentials are read from environment configuration rather than embedded directly into source code.

### Evidence before interpretation

Deterministic evidence comes first; AI interpretation comes after.

### Human in the loop

NEXUS does not autonomously perform destructive security actions.

### Runtime data separation

Network observations, state files, logs, HTB sessions, and other environment-specific runtime artifacts should remain outside the public source tree.

---

# 🚀 Current Project Status

NEXUS is an **active engineering project**.

Current major capabilities include:

- [x] Continuous network monitoring
- [x] Structured switch parsing
- [x] Persistent device identity
- [x] Device/network history
- [x] Topology construction
- [x] Topology diffing
- [x] Event classification
- [x] Event lifecycle / resolution
- [x] Network intelligence correlation
- [x] Local Blue AI
- [x] AI response validation
- [x] AI freshness / trigger state
- [x] Red Team planning layer
- [x] Safe event simulation
- [x] Jetson hardware health
- [x] Thermal telemetry
- [x] Thermal incident lifecycle
- [x] OLED output
- [x] CUBE LED output
- [x] Critical audio alerting
- [x] HTB service/version inventory
- [x] NVD CVE research
- [x] Exploit-DB references
- [x] Condition-by-condition evidence
- [x] Deterministic exploitability state
- [x] Interactive HTB operator workflow
- [x] Mobile-friendly dashboard

### In progress / next engineering targets

- Public deployment documentation
- Portable systemd installation
- Expanded automated tests
- Dashboard modularization
- Better service/version detection
- Richer CVE condition matching
- More hardware telemetry
- Additional visualization and incident workflow

---

# 🛠️ Local Development

NEXUS is primarily developed and tested on Linux/Jetson hardware.

The public repository intentionally excludes environment-specific runtime state and credentials.

A typical local environment needs components such as:

```text
Python 3
OpenSSH
pexpect
psutil
Pillow
luma.oled
Ollama (optional for AI features)
Jetson/CUBE hardware libraries (optional for hardware features)
```

The exact deployment configuration is environment-specific and is intentionally kept separate from secrets and runtime state.

---

# 🧭 Example Operator Workflows

## Monitor the network

```text
Switch
  ↓
NEXUS collection
  ↓
Diff
  ↓
Event lifecycle
  ↓
Intelligence
  ↓
Dashboard
```

## Investigate a security situation

```text
Observed event
      ↓
Evidence review
      ↓
NEXUS intelligence
      ↓
Blue AI advisory
      ↓
Red Team validation plan
      ↓
Human investigation
```

## Research an HTB target

```text
Nmap
  ↓
Service/version parser
  ↓
CVE research
  ↓
Conditions
  ↓
Evidence
  ↓
Exploitability assessment
  ↓
Operator decision
```

---

# 📚 Engineering Lessons Demonstrated

One of the goals of NEXUS is to demonstrate practical software engineering and security engineering concepts in one project.

### State machines

Network events, thermal events, alerts, and AI freshness all require explicit state handling.

### Data modeling

Raw CLI output is transformed into structured representations before being used by higher-level components.

### Validation

AI output is treated as untrusted input and validated before being accepted as an advisory result.

### Persistence

History matters. NEXUS stores state across monitoring cycles so behavior can be evaluated over time.

### Fault tolerance

Individual stages are designed so optional components do not unnecessarily destroy the core monitoring loop.

### Security boundaries

The operator, deterministic monitor, advisory AI, Red Team planner, and hardware outputs are intentionally separated.

### Observability

The system exposes not only conclusions, but also the evidence and lifecycle information behind those conclusions.

---

# 🏆 Why This Project Exists

NEXUS is being built as a practical bridge between:

**software engineering + networking + cybersecurity + Linux + embedded hardware + AI.**

Rather than building a demo that calls an LLM and displays its answer, the project focuses on the harder engineering problems around AI-assisted security systems:

- What is actually observed?
- What changed?
- Is the change still active?
- What evidence supports the conclusion?
- What does the model know versus assume?
- Can the model's output be validated?
- Can an operator reproduce the reasoning?
- Can the entire system be tested safely?

That is the problem NEXUS is trying to solve.

---

# 👨‍💻 Author

**Dorian Calderon**

Cybersecurity-focused software engineering project.

Built around hands-on Linux, networking, Python, embedded hardware, automation, defensive monitoring, and local AI experimentation.

---

# ⚠️ Responsible Use

NEXUS is intended for systems and environments you are authorized to monitor or test.

The HTB/operator functionality is designed for authorized labs and controlled security research. Public vulnerability references are provided for research and validation workflows; users are responsible for applying appropriate authorization and safety boundaries.

---

## ⭐ Project Direction

NEXUS is still evolving.

The long-term goal is a system where network evidence, device history, security intelligence, AI advisory analysis, authorized research tooling, and physical hardware feedback operate as one coherent local security platform—while keeping deterministic evidence and human oversight at the center.

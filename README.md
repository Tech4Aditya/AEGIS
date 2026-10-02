# AEGIS v0.6 — Autonomous Enterprise Guard & Investigation System

## JAI 2026 / Agentic AI Cybersecurity

AEGIS is a local-first autonomous SOC prototype with a real agent architecture:

**Detect → Plan → Gather Evidence → Reason → Decide → Policy Gate → Human Approval / Response → Verify → Audit → Learn**

### Implemented

- JIIT-style enterprise security dashboard
- Live investigation stream over WebSocket
- 7-agent workflow
- Structured mission planner
- Tool registry with bounded security tools
- Optional OpenAI-compatible LLM adapter
- Deterministic fallback planner when no LLM is configured
- Explainable confidence scoring with evidence contributions
- Contradiction / missing-telemetry penalties
- Deterministic policy engine
- Human approval queue
- Approve / reject actions
- Rollback of simulated containment
- Persistent PostgreSQL storage
- Redis event bus
- SQLite local fallback for zero-infrastructure demo
- Synthetic cyber range
- 20+ ARES evaluation scenarios
- ARES automated regression/evaluation engine
- Host inventory
- Synthetic threat intelligence
- Evidence graph
- Incident reports
- Audit trail
- Global search
- Agent performance
- Policy Center
- Settings
- API docs through FastAPI

### Quick start — recommended

```powershell
docker compose up --build
```

Open:

http://localhost:18080

Services:
- AEGIS API/UI: 18080
- PostgreSQL: 55432
- Redis: 56379

The application automatically uses PostgreSQL and Redis in Docker.

### Optional real LLM

Set:

```powershell
$env:LLM_BASE_URL="https://api.openai.com/v1"
$env:LLM_API_KEY="YOUR_KEY"
$env:LLM_MODEL="YOUR_MODEL"
```

Then restart the container.

The agent layer uses the LLM for structured planning/reasoning, but never gives the model unrestricted execution access.

### Safety architecture

```text
             LLM / Planner
                   |
                   v
            Tool Registry
                   |
                   v
         Evidence / Observations
                   |
                   v
        Decision + Confidence
                   |
                   v
        Deterministic Policy Gate
             /           \
          AUTO          HUMAN
           |              |
           v              v
      Bounded Tool    Approval Queue
           |              |
           +------->------+
                   |
                   v
              Verification
                   |
                   v
                 Audit
```

### ARES

ARES is the autonomous evaluation engine. It runs safe synthetic scenarios and scores:

- Detection
- Investigation completion
- Decision correctness
- Safe-response behavior
- False containment
- Escalation correctness
- Rollback success

Run:

```http
POST /api/ares/run
```

or open **Attack Simulation → ARES Evaluation**.

### Important boundary

All response actions are simulated against synthetic hosts. No arbitrary shell execution, exploitation, public-target scanning, credential theft, persistence or offensive automation is implemented.

This is intentional: the competition demo shows autonomous reasoning and bounded defensive response without creating an offensive tool.

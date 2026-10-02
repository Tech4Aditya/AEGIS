# AEGIS architecture

```text
                       Web Dashboard
                            |
                         WebSocket
                            |
                       FastAPI API
                            |
                    Mission Orchestrator
                            |
        +-------------------+-------------------+
        |                   |                   |
      Planner          Tool Registry       Evidence Store
        |                   |                   |
        +-------------------+-------------------+
                            |
                       Threat Analyst
                            |
                     Confidence Engine
                            |
                      Decision Agent
                            |
                    Deterministic Policy
                       /           \
                    AUTO          HUMAN
                     |              |
                Response Tool   Approval Queue
                     |              |
                     +------+- -----+
                            |
                       Verification
                            |
                         Audit Log
                            |
                    PostgreSQL / Redis
                            |
                           ARES
```

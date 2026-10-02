# AEGIS Code Review Rules

You are reviewing AEGIS, an autonomous cybersecurity
investigation and response platform.

Prioritize:

## 1. Security
- Never introduce arbitrary command execution.
- Never bypass Policy Guardian.
- Never allow LLM output to directly execute privileged actions.
- All response actions must pass policy validation.
- Prefer reversible actions.

## 2. Agentic Architecture
Check that:
- Planner does not directly execute tools.
- Investigator gathers evidence before decisions.
- Decision Agent does not bypass Policy Guardian.
- Response Agent only executes approved actions.
- Verification runs after response.
- Human approval is required for high-risk actions.

## 3. Reliability
Check:
- database failures
- Redis failures
- malformed LLM output
- missing evidence
- low-confidence decisions
- rollback failures
- duplicate events

## 4. Testing
Every security-sensitive change should include tests.

Check:
- unit tests
- API tests
- scenario tests
- ARES regression tests

## 5. Review severity

CRITICAL:
Security bypass, arbitrary execution,
unauthorized containment, credential exposure.

HIGH:
Policy bypass, broken rollback,
unsafe autonomous response.

MEDIUM:
Reliability or maintainability issue.

LOW:
Style/documentation improvements.

Do not complain about stylistic issues unless they
materially affect maintainability or security.
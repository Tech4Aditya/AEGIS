# AEGIS Code Review Instructions

AEGIS is an autonomous cybersecurity investigation and response platform.

When reviewing code:

## Security

Check for:

- Policy Guardian bypasses
- unauthorized privileged actions
- arbitrary command execution
- unsafe tool execution
- hardcoded secrets
- credential leakage
- insecure API endpoints
- unsafe deserialization
- missing authorization checks

## Agent Architecture

Verify that:

- Planner does not directly execute tools
- Investigator gathers evidence before decisions
- Decision Agent cannot bypass Policy Guardian
- Response Agent only executes authorized actions
- Verification happens after response
- high-risk actions can require human approval

## Reliability

Look for:

- database failure handling
- Redis failure handling
- malformed LLM responses
- missing evidence
- low-confidence decisions
- rollback failures
- duplicate events
- race conditions

## Testing

Security-sensitive changes should include tests.

Prefer:

- unit tests
- API tests
- scenario tests
- ARES regression tests

## Severity

CRITICAL:
Security bypass or unauthorized execution.

HIGH:
Unsafe autonomous response, broken policy enforcement,
broken rollback, or privilege escalation.

MEDIUM:
Reliability or significant maintainability issue.

LOW:
Minor maintainability/documentation issue.

Focus on real security and correctness problems.
Do not generate unnecessary stylistic complaints.
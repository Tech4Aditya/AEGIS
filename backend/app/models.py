from pydantic import BaseModel, Field
from typing import Any, Optional

class Event(BaseModel):
    id: str
    timestamp: str
    host: str
    kind: str
    actor: str = "system"
    source: str
    severity: str
    data: dict[str, Any] = Field(default_factory=dict)

class Evidence(BaseModel):
    id: str
    event_id: str
    title: str
    detail: str
    weight: float
    source: str
    contribution: float = 0
    confidence_effect: str = ""

class AgentRun(BaseModel):
    agent: str
    status: str
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)
    timestamp: str

class Incident(BaseModel):
    id: str
    created_at: str
    scenario: str
    host: str
    status: str = "NEW"
    severity: str = "MEDIUM"
    confidence: float = 0
    summary: str = ""
    events: list[Event] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    decision: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)
    response: dict[str, Any] = Field(default_factory=dict)
    verification: dict[str, Any] = Field(default_factory=dict)
    agents: list[AgentRun] = Field(default_factory=list)
    plan: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    confidence_trace: dict[str, Any] = Field(default_factory=dict)
    approval: dict[str, Any] = Field(default_factory=dict)
    rollback: dict[str, Any] = Field(default_factory=dict)

class AuditRecord(BaseModel):
    id: str
    timestamp: str
    actor: str
    action: str
    target: str
    reason: str
    result: str
    incident_id: str
    evidence_ids: list[str] = Field(default_factory=list)

class ApprovalRequest(BaseModel):
    approval_id: str
    incident_id: str
    action: str
    target: str
    confidence: float
    reason: str
    status: str
    created_at: str

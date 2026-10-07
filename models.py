"""Validated API request and response models."""
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, conlist, constr

AgentId = constr(strip_whitespace=True, min_length=1, max_length=128)
Action = constr(strip_whitespace=True, min_length=1, max_length=256)
NonEmptyString = Action
ManifestSignature = constr(strict=True, max_length=128)
AllowedActions = conlist(Action, min_length=1, max_length=100)


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuditLogProof(APIModel):
    """SHA-256 digest signed by the agent; timestamp is covered by the signature."""
    digest: StrictStr
    created_at: datetime
    signature: Optional[ManifestSignature] = None


class PermissionsManifest(APIModel):
    """Allowed actions plus a base64 Ed25519 signature over the canonical manifest."""
    allowed_actions: AllowedActions
    signature: Optional[ManifestSignature] = None


class ScoreRequest(APIModel):
    agent_id: AgentId
    permission_manifest: Optional[PermissionsManifest] = None
    audit_log: Optional[AuditLogProof] = None
    incident_count: StrictInt = Field(ge=0, le=1_000_000)


class AgentRegistrationRequest(APIModel):
    agent_id: AgentId


class AgentRegistrationResponse(APIModel):
    agent_id: str
    api_key: str


class AgentKeyRotationRequest(APIModel):
    agent_id: AgentId


class AgentKeyRotationResponse(APIModel):
    agent_id: str
    api_key: str


class HealthResponse(APIModel):
    status: Literal["ok"]
    api_version: str


class ChallengeRequest(APIModel):
    agent_id: AgentId


class VerifyIdentityRequest(APIModel):
    agent_id: AgentId
    challenge_id: NonEmptyString
    signature: NonEmptyString


class EvidenceResult(APIModel):
    valid: bool
    verification: Literal["cryptographic", "structure"]
    reason: str


class ScoreEvidenceResults(APIModel):
    identity_verified: EvidenceResult
    permission_declared: EvidenceResult
    audit_log: EvidenceResult


class ScoreResponse(APIModel):
    agent_id: str
    score: int
    rating: Literal["high_score", "review", "low_score"]
    reason: str
    checked_at: str
    evidence_results: ScoreEvidenceResults




class FactorScore(APIModel):
    factor: Literal["identity_verified", "permission_declared", "audit_log", "incidents"]
    points: int
    max_points: int
    status: Literal["verified", "failed", "applied"]
    verification: Optional[Literal["cryptographic", "structure"]] = None
    reason: str


class TrustReportResponse(APIModel):
    agent_id: str
    overall_score: int
    rating: Literal["high_score", "review", "low_score"]
    base_score: int
    factor_scores: List[FactorScore]
    evidence_results: ScoreEvidenceResults
    reasons: List[str]
    checked_at: str


class ChallengeResponse(APIModel):
    agent_id: str
    challenge_id: str
    challenge: str
    expires_at: str


class VerifyIdentityResponse(APIModel):
    agent_id: str
    verified: bool
    reason: str
    checked_at: str

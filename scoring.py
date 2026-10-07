"""Evidence evaluation and score calculation."""
from typing import Literal

from models import (
    FactorScore,
    ScoreEvidenceResults,
    ScoreRequest,
    ScoreResponse,
    TrustReportResponse,
)
from security import (
    current_identity_result,
    now_utc,
    utc_text,
    verify_audit_proof,
    verify_permissions_manifest,
)


def rating_for_score(score: int) -> Literal["high_score", "review", "low_score"]:
    if score >= 80:
        return "high_score"
    if score >= 50:
        return "review"
    return "low_score"


def build_trust_report(request: ScoreRequest) -> TrustReportResponse:
    evidence = ScoreEvidenceResults(
        identity_verified=current_identity_result(request.agent_id),
        permission_declared=verify_permissions_manifest(request.agent_id, request.permission_manifest),
        audit_log=verify_audit_proof(request.agent_id, request.audit_log),
    )
    factors = [
        ("identity_verified", evidence.identity_verified),
        ("permission_declared", evidence.permission_declared),
        ("audit_log", evidence.audit_log),
    ]
    factor_scores = [
        FactorScore(
            factor=name,
            points=15 if result.valid else 0,
            max_points=15,
            status="verified" if result.valid else "failed",
            verification=result.verification,
            reason=result.reason,
        )
        for name, result in factors
    ]
    incident_penalty = -10 * request.incident_count
    incident_word = "incident" if request.incident_count == 1 else "incidents"
    factor_scores.append(FactorScore(
        factor="incidents",
        points=incident_penalty,
        max_points=0,
        status="applied",
        reason=(f"{request.incident_count} {incident_word}: {incident_penalty} points."
                if request.incident_count else "No incident penalty applied."),
    ))

    raw_score = 50 + sum(component.points for component in factor_scores)
    overall_score = max(0, min(100, raw_score))
    failed = [result.reason for _, result in factors if not result.valid]
    reasons = failed or ["All three evidence checks passed."]
    if request.incident_count:
        reasons.append(f"{request.incident_count} {incident_word} reduced the score by {abs(incident_penalty)} points.")
    if raw_score != overall_score:
        reasons.append(f"Raw score {raw_score} was clamped to {overall_score}.")

    return TrustReportResponse(
        agent_id=request.agent_id,
        overall_score=overall_score,
        rating=rating_for_score(overall_score),
        base_score=50,
        factor_scores=factor_scores,
        evidence_results=evidence,
        reasons=reasons,
        checked_at=utc_text(now_utc()),
    )


def score_agent(request: ScoreRequest) -> ScoreResponse:
    """Preserve the compact response while sharing report evidence evaluation."""
    report = build_trust_report(request)
    passed = sum(result.valid for result in (
        report.evidence_results.identity_verified,
        report.evidence_results.permission_declared,
        report.evidence_results.audit_log,
    ))
    failed = [
        (name, result)
        for name, result in (
            ("identity_verified", report.evidence_results.identity_verified),
            ("permission_declared", report.evidence_results.permission_declared),
            ("audit_log", report.evidence_results.audit_log),
        )
        if not result.valid
    ]
    incident_word = "incident" if request.incident_count == 1 else "incidents"
    incident_summary = (
        f"{request.incident_count} {incident_word} applied, subtracting {abs(-10 * request.incident_count)} points."
        if request.incident_count
        else "No incidents applied."
    )
    if failed:
        details = "; ".join(f"{name}: {result.reason}" for name, result in failed)
        reason = f"{passed} of 3 evidence checks passed. {incident_summary} Failed checks: {details}"
    else:
        reason = f"All 3 evidence checks passed. {incident_summary}"
    return ScoreResponse(
        agent_id=report.agent_id,
        score=report.overall_score,
        rating=report.rating,
        reason=reason,
        checked_at=report.checked_at,
        evidence_results=report.evidence_results,
    )

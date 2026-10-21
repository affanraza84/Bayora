"""
Bayora Shield - SQLAlchemy 2.x Database Models
Implements relational schema per docs/data-model.md with UUIDs, foreign keys,
uniqueness constraints, and proper indexes.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    String,
    Text,
    Boolean,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    BigInteger,
    CheckConstraint,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    # Relationships
    users: Mapped[List["User"]] = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    policy_versions: Mapped[List["PolicyVersion"]] = relationship("PolicyVersion", back_populates="tenant", cascade="all, delete-orphan")
    runs: Mapped[List["EvaluationRun"]] = relationship("EvaluationRun", back_populates="tenant", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="tenant", cascade="all, delete-orphan")
    artifacts: Mapped[List["Artifact"]] = relationship("Artifact", back_populates="tenant", cascade="all, delete-orphan")
    audit_events: Mapped[List["AuditEvent"]] = relationship("AuditEvent", back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # platform_admin, auditor, red_lead, red_operator, blue_lead, blue_operator
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")

    __table_args__ = (
        CheckConstraint(
            "role IN ('platform_admin', 'auditor', 'red_lead', 'red_operator', 'blue_lead', 'blue_operator', 'svc:control-plane', 'svc:evaluator', 'svc:audit-service')",
            name="check_valid_role",
        ),
    )


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_label: Mapped[str] = mapped_column(String(50), nullable=False)
    config_schema: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    rules_checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="policy_versions")
    runs: Mapped[List["EvaluationRun"]] = relationship("EvaluationRun", back_populates="policy_version")

    __table_args__ = (
        UniqueConstraint("tenant_id", "version_label", name="uq_tenant_policy_version"),
    )


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_version_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True
    )
    target_model: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), default="created", nullable=False
    )  # created, queued, running, completed, failed
    total_tests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    breach_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="runs")
    policy_version: Mapped[Optional["PolicyVersion"]] = relationship("PolicyVersion", back_populates="runs")
    test_cases: Mapped[List["TestCase"]] = relationship("TestCase", back_populates="run", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
    artifacts: Mapped[List["Artifact"]] = relationship("Artifact", back_populates="run", cascade="all, delete-orphan")
    evidence_bundle: Mapped[Optional["EvidenceBundle"]] = relationship("EvidenceBundle", back_populates="run", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint(
            "status IN ('created', 'queued', 'running', 'completed', 'failed')",
            name="check_valid_run_status",
        ),
        Index("idx_runs_tenant_status", "tenant_id", "status"),
    )


class TestCase(Base):
    __tablename__ = "test_cases"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # PROMPT_INJECTION, JAILBREAK, DATA_EXFILTRATION, SYSTEM_PROMPT_LEAK, RESOURCE_DOS
    payload_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    guardrail_decision: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # PERMITTED, BLOCKED_INPUT, BLOCKED_OUTPUT
    breach_status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # NO_BREACH, CONFIRMED_BREACH, PARTIAL_LEAK, UNKNOWN
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    run: Mapped["EvaluationRun"] = relationship("EvaluationRun", back_populates="test_cases")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="test_case")

    __table_args__ = (
        CheckConstraint(
            "category IN ('PROMPT_INJECTION', 'JAILBREAK', 'DATA_EXFILTRATION', 'SYSTEM_PROMPT_LEAK', 'RESOURCE_DOS')",
            name="check_valid_category",
        ),
        CheckConstraint(
            "guardrail_decision IN ('PERMITTED', 'BLOCKED_INPUT', 'BLOCKED_OUTPUT')",
            name="check_valid_decision",
        ),
        CheckConstraint(
            "breach_status IN ('NO_BREACH', 'CONFIRMED_BREACH', 'PARTIAL_LEAK', 'UNKNOWN')",
            name="check_valid_breach_status",
        ),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    test_case_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("test_cases.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    cwe_id: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    redacted_proof: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="findings")
    run: Mapped["EvaluationRun"] = relationship("EvaluationRun", back_populates="findings")
    test_case: Mapped[Optional["TestCase"]] = relationship("TestCase", back_populates="findings")

    __table_args__ = (
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')",
            name="check_valid_severity",
        ),
        Index("idx_findings_tenant_severity", "tenant_id", "severity"),
    )


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=True
    )
    owner_role: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # red, blue, audit
    storage_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="artifacts")
    run: Mapped[Optional["EvaluationRun"]] = relationship("EvaluationRun", back_populates="artifacts")

    __table_args__ = (
        CheckConstraint(
            "owner_role IN ('red', 'blue', 'audit')",
            name="check_valid_owner_role",
        ),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    # Monotonically increasing sequence number (primary key)
    sequence_number: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    event_id: Mapped[str] = mapped_column(
        String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )
    policy_version: Mapped[str] = mapped_column(String(100), default="unknown", nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="audit_events")

    __table_args__ = (
        Index("idx_audit_tenant_time", "tenant_id", "timestamp"),
        Index("idx_audit_event_hash", "event_hash"),
    )


class EvidenceBundle(Base):
    __tablename__ = "evidence_bundles"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evaluation_runs.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    bundle_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    bundle_checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ed25519_signature: Mapped[str] = mapped_column(Text, nullable=False)
    signer_key_id: Mapped[str] = mapped_column(String(100), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=get_utc_now, nullable=False
    )

    run: Mapped["EvaluationRun"] = relationship("EvaluationRun", back_populates="evidence_bundle")

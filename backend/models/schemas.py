"""
Pydantic request schemas — the first line of input validation.

`extra="forbid"` rejects unexpected fields (mass-assignment protection) and
every string has a maximum length (resource-exhaustion protection). Semantic
checks (valid IPs, supported protocols...) happen in ids.validation.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ids.config import ALERT_STATUSES, SEVERITIES

Status = Literal[ALERT_STATUSES]  # type: ignore[valid-type]
Severity = Literal[SEVERITIES]    # type: ignore[valid-type]


class FlowIn(BaseModel):
    """A network-flow record submitted by a sensor / the simulator."""
    model_config = ConfigDict(extra="forbid")

    flow_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:\-]{1,64}$")
    timestamp: str | None = Field(default=None, max_length=40)
    source_ip: str = Field(max_length=45)
    destination_ip: str = Field(max_length=45)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = Field(max_length=10)
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    duration_seconds: float = Field(default=0.0, ge=0)
    connection_count: int = Field(default=1, ge=0)
    failed_connection_count: int = Field(default=0, ge=0)
    syn_count: int = Field(default=0, ge=0)
    rst_count: int = Field(default=0, ge=0)
    average_packet_size: float | None = Field(default=None, ge=0)
    # Optional synthetic ground truth — lets us measure detection accuracy live.
    label: Literal["NORMAL", "SUSPICIOUS"] | None = None
    scenario_type: str | None = Field(default=None, max_length=40, pattern=r"^[A-Z_]+$")


def _clean_text(value: str) -> str:
    """Strip control characters (except newlines/tabs) and surrounding whitespace."""
    cleaned = "".join(ch for ch in value if ch in "\n\t" or ch.isprintable())
    return cleaned.strip()


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Status
    note: str | None = Field(default=None, max_length=2000,
                             description="Required when closing (RESOLVED / FALSE_POSITIVE)")

    @field_validator("note")
    @classmethod
    def clean_note(cls, v):
        return _clean_text(v) if v is not None else v


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=1, max_length=2000)

    @field_validator("note")
    @classmethod
    def clean_note(cls, v):
        v = _clean_text(v)
        if not v:
            raise ValueError("note must contain visible text")
        return v


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    severity: Severity | None = None
    threshold: dict | None = None

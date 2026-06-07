"""Pydantic models for IOC management."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"


class IOCSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IOCEntry(BaseModel):
    id: str
    type: IOCType
    value: str
    source: str = "manual"
    severity: IOCSeverity = IOCSeverity.HIGH
    confidence: float = 1.0
    first_seen: datetime
    last_seen: datetime
    notes: str = ""
    active: bool = True
    tags: list[str] = Field(default_factory=list)


class IOCCreate(BaseModel):
    type: IOCType
    value: str
    severity: IOCSeverity = IOCSeverity.HIGH
    confidence: float = 1.0
    notes: str = ""
    tags: list[str] = Field(default_factory=list)


class IOCUpdate(BaseModel):
    severity: Optional[IOCSeverity] = None
    confidence: Optional[float] = None
    notes: Optional[str] = None
    active: Optional[bool] = None
    tags: Optional[list[str]] = None


class IOCBulkImport(BaseModel):
    entries: list[IOCCreate]


class IOCStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_source: dict[str, int]
    by_severity: dict[str, int]
    active: int
    inactive: int


class FeedType(str, Enum):
    """Supported IOC feed provider types."""
    URLHAUS = "urlhaus"
    THREATFOX = "threatfox"
    OTX = "otx"
    ABUSEIPDB = "abuseipdb"
    MISP = "misp"
    OPENCTI = "opencti"
    VIRUSTOTAL = "virustotal"
    SHODAN = "shodan"
    CIRCL = "circl"
    CUSTOM = "custom"


class FeedConfig(BaseModel):
    id: str
    name: str
    feed_type: FeedType
    enabled: bool
    url: str = ""
    api_key_configured: bool
    auth_header: str = ""  # e.g. "Authorization", "X-Api-Key"
    last_run: Optional[datetime] = None
    last_count: int = 0
    last_error: str = ""
    interval_minutes: int = 1440  # default 24h
    min_confidence: float = 0.7
    ioc_types: list[str] = Field(default_factory=lambda: ["domain", "ip", "url", "hash_sha256"])
    created_at: Optional[datetime] = None


class FeedCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    feed_type: FeedType
    url: str = ""
    api_key: str = ""  # stored encrypted, never returned
    auth_header: str = ""
    enabled: bool = True
    interval_minutes: int = Field(default=1440, ge=5, le=44640)  # 5min to 31 days
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    ioc_types: list[str] = Field(default_factory=lambda: ["domain", "ip", "url", "hash_sha256"])


class FeedUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    enabled: Optional[bool] = None
    url: Optional[str] = None
    api_key: Optional[str] = None  # if provided, update the key
    auth_header: Optional[str] = None
    interval_minutes: Optional[int] = Field(default=None, ge=5, le=44640)
    min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    ioc_types: Optional[list[str]] = None

"""Admin API routes for agent discovery and Shadow AI monitoring."""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from admin.models.auth import TokenPayload
from admin.services.auth_service import require_permission
from src.discovery.agent_discovery import (
    AgentDiscovery,
    DiscoveredAgent,
    KNOWN_PORTS,
    KNOWN_PATHS,
)
from src.discovery.shadow_ai import ShadowAIMonitor, ShadowAIAlert
from src.discovery.mcp_inventory import (
    MCPInventory,
    MCPTool,
    MCPServer,
    RiskAssessment,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/discovery", tags=["discovery"])


# --- Request/Response models ---


class NetworkScanRequest(BaseModel):
    """Request to scan network targets for LLM agents."""
    targets: list[str] = Field(..., min_length=1, description="List of hostnames or IPs to scan")
    timeout: float = Field(5.0, ge=1.0, le=60.0, description="Probe timeout in seconds")


class KubernetesScanRequest(BaseModel):
    """Request to scan a Kubernetes namespace."""
    namespace: str = Field("default", description="Kubernetes namespace to scan")


class DiscoveredAgentResponse(BaseModel):
    """Serialized discovered agent."""
    host: str
    port: int
    service_type: str
    confidence: float
    discovered_at: str
    metadata: dict = Field(default_factory=dict)


class NetworkScanResponse(BaseModel):
    """Response from a network or Kubernetes scan."""
    agents: list[DiscoveredAgentResponse]
    total_found: int
    scan_targets: list[str] = Field(default_factory=list)


class DiscoveryStatusResponse(BaseModel):
    """Discovery capabilities status."""
    enabled: bool
    known_ports: list[int]
    known_paths: list[str]
    shadow_ai_endpoints_count: int
    mcp_inventory_available: bool


class TrafficLogEntry(BaseModel):
    """Single traffic log entry for shadow AI analysis."""
    hostname: str
    source_ip: str | None = None
    timestamp: str | None = None


class AnalyzeTrafficRequest(BaseModel):
    """Request to analyze traffic logs for shadow AI usage."""
    log_entries: list[TrafficLogEntry] = Field(..., min_length=1, description="Traffic log entries")


class ShadowAIAlertResponse(BaseModel):
    """Serialized shadow AI alert."""
    hostname: str
    service: str
    timestamp: str
    source_ip: str | None = None
    risk_level: str


class ClassifyHostnameRequest(BaseModel):
    """Request to classify a single hostname."""
    hostname: str = Field(..., min_length=1, description="Hostname to classify")


class ClassifyHostnameResponse(BaseModel):
    """Classification result for a hostname."""
    hostname: str
    service: str | None
    is_known_ai: bool


class MCPStatusResponse(BaseModel):
    """MCP inventory status."""
    available: bool
    capabilities: list[str]


class MCPAssessRiskRequest(BaseModel):
    """Request to assess risk of an MCP tool."""
    name: str = Field(..., min_length=1, description="Tool name")
    description: str = Field("", description="Tool description")
    capabilities: list[str] = Field(default_factory=list, description="Tool capabilities")


class MCPRiskAssessmentResponse(BaseModel):
    """Risk assessment result."""
    score: float
    findings: list[str]
    recommendations: list[str]


class MCPEnumerateRequest(BaseModel):
    """Request to enumerate tools on an MCP server."""
    server_url: str = Field(..., min_length=1, description="MCP server URL")


class MCPToolResponse(BaseModel):
    """Serialized MCP tool."""
    name: str
    description: str
    parameters: dict = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)


class MCPEnumerateResponse(BaseModel):
    """Response from MCP tool enumeration."""
    server_url: str
    tools: list[MCPToolResponse]
    total_tools: int


# --- Endpoints ---


@router.get("/status", response_model=DiscoveryStatusResponse)
def discovery_status(
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> DiscoveryStatusResponse:
    """Return discovery capabilities status."""
    monitor = ShadowAIMonitor()
    return DiscoveryStatusResponse(
        enabled=True,
        known_ports=KNOWN_PORTS,
        known_paths=KNOWN_PATHS,
        shadow_ai_endpoints_count=len(monitor.KNOWN_AI_ENDPOINTS),
        mcp_inventory_available=True,
    )


@router.post("/scan/network", response_model=NetworkScanResponse)
async def scan_network(
    req: NetworkScanRequest,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> NetworkScanResponse:
    """Scan network targets for LLM agents."""
    discovery = AgentDiscovery(timeout=req.timeout)
    try:
        agents = await discovery.scan_network(req.targets)
    except Exception as exc:
        logger.error("Network scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Network scan failed: {exc}")

    agent_responses = [DiscoveredAgentResponse(**asdict(a)) for a in agents]
    return NetworkScanResponse(
        agents=agent_responses,
        total_found=len(agent_responses),
        scan_targets=req.targets,
    )


@router.post("/scan/kubernetes", response_model=NetworkScanResponse)
async def scan_kubernetes(
    req: KubernetesScanRequest,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> NetworkScanResponse:
    """Scan Kubernetes namespace for LLM agents."""
    discovery = AgentDiscovery()
    try:
        agents = await discovery.scan_kubernetes(namespace=req.namespace)
    except Exception as exc:
        logger.error("Kubernetes scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Kubernetes scan failed: {exc}")

    agent_responses = [DiscoveredAgentResponse(**asdict(a)) for a in agents]
    return NetworkScanResponse(
        agents=agent_responses,
        total_found=len(agent_responses),
        scan_targets=[f"namespace:{req.namespace}"],
    )


@router.get("/shadow-ai/endpoints", response_model=list[str])
def shadow_ai_endpoints(
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> list[str]:
    """Return known AI endpoints blocklist."""
    monitor = ShadowAIMonitor()
    return monitor.get_blocklist()


@router.post("/shadow-ai/analyze", response_model=list[ShadowAIAlertResponse])
def shadow_ai_analyze(
    req: AnalyzeTrafficRequest,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> list[ShadowAIAlertResponse]:
    """Analyze traffic log for shadow AI usage."""
    monitor = ShadowAIMonitor()
    log_entries = [entry.model_dump() for entry in req.log_entries]
    alerts = monitor.analyze_traffic_log(log_entries)
    return [ShadowAIAlertResponse(**asdict(a)) for a in alerts]


@router.post("/shadow-ai/classify", response_model=ClassifyHostnameResponse)
def shadow_ai_classify(
    req: ClassifyHostnameRequest,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> ClassifyHostnameResponse:
    """Classify a single hostname as AI service or not."""
    monitor = ShadowAIMonitor()
    service = monitor.classify_endpoint(req.hostname)
    return ClassifyHostnameResponse(
        hostname=req.hostname,
        service=service,
        is_known_ai=service is not None,
    )


@router.get("/mcp/status", response_model=MCPStatusResponse)
def mcp_status(
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> MCPStatusResponse:
    """Return MCP inventory status."""
    return MCPStatusResponse(
        available=True,
        capabilities=["enumerate_tools", "assess_risk", "monitor_usage"],
    )


@router.post("/mcp/assess-risk", response_model=MCPRiskAssessmentResponse)
def mcp_assess_risk(
    req: MCPAssessRiskRequest,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> MCPRiskAssessmentResponse:
    """Assess risk of an MCP tool."""
    inventory = MCPInventory()
    tool = MCPTool(
        name=req.name,
        description=req.description,
        capabilities=req.capabilities,
    )
    assessment = inventory.assess_risk(tool)
    return MCPRiskAssessmentResponse(**asdict(assessment))


@router.post("/mcp/enumerate", response_model=MCPEnumerateResponse)
async def mcp_enumerate(
    req: MCPEnumerateRequest,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> MCPEnumerateResponse:
    """Enumerate tools on an MCP server."""
    inventory = MCPInventory()
    try:
        tools = await inventory.enumerate_tools(req.server_url)
    except Exception as exc:
        logger.error("MCP enumeration failed for %s: %s", req.server_url, exc)
        raise HTTPException(
            status_code=500,
            detail=f"MCP tool enumeration failed: {exc}",
        )

    tool_responses = [MCPToolResponse(**asdict(t)) for t in tools]
    return MCPEnumerateResponse(
        server_url=req.server_url,
        tools=tool_responses,
        total_tools=len(tool_responses),
    )

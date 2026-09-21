"""Operator-owned uvicorn factory reference; intentionally has no bundled tools.

Place reviewed async handlers and closed argument models in this module, or use
explicit static imports from operator-owned packages baked into the approved image.
Do not turn environment strings or agent arguments into import/callable names.

Helm selects this module at deployment time, never from request data. See
docs/EXECUTOR-DEPLOYMENT.md. The operator must also supply a separate authorizer
that authorizes each business operation before signing its bound action token.
Read BULWARK_EXECUTOR_TOOL_CREDENTIAL_FILE only during factory initialization;
capture the credential in the reviewed handler's client closure and register it
as a SecretStr protected_value. Never add credentials to tool arguments/results.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from src.executor.app import ExecutorSettings, RegisteredTool, create_app
from src.executor.replay import RedisReplayStore
from src.guardrails.tool_policy import AgentPolicy

# Operator must populate all three explicitly. Empty wiring fails closed.
TOOLS: dict[str, RegisteredTool] = {}
POLICIES: list[AgentPolicy] = []
PRINCIPALS: frozenset[tuple[str, str, str]] = frozenset()


def create_executor():
    """No I/O occurs until uvicorn calls this factory; no debug/shared JWT secret."""
    if not TOOLS or not POLICIES or not PRINCIPALS:
        raise RuntimeError("Operator tools, strict policies and principals must be configured")
    # Only a verification key reaches the executor. The issuer's private key must
    # remain in a separate trusted authorizer, never in the agent or this process.
    settings = ExecutorSettings(
        public_key_pem=Path(os.environ["BULWARK_EXECUTOR_PUBLIC_KEY_FILE"]).read_text(encoding="ascii"),
        issuer=os.environ["BULWARK_EXECUTOR_ISSUER"],
        audience=os.environ["BULWARK_EXECUTOR_AUDIENCE"],
        development=False,
        workers=1,
        replicas=1,
    )
    if os.environ.get("BULWARK_EXECUTOR_REPLAY_DURABILITY_CONFIRMED") != "true":
        raise RuntimeError("Durable replay infrastructure must be reviewed before enabling execution")
    client = get_redis_client()
    replay = RedisReplayStore(client, durability_confirmed=True)
    app = create_app(settings=settings, tools=TOOLS, policies=POLICIES,
                     principals=PRINCIPALS, replay_store=replay)

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            await client.aclose()

    app.router.lifespan_context = lifespan
    return app


def get_redis_client():
    """Standalone helper; static imports, verified TLS, mounted secret, no retries.

    The operator can replace this with its existing approved client helper. Never
    import the admin lifespan or its global DB/config just to obtain a client.
    """
    from redis.asyncio import Redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    password = Path(os.environ["BULWARK_EXECUTOR_REDIS_PASSWORD_FILE"]).read_text(encoding="utf-8").strip()
    if not password:
        raise RuntimeError("Redis authentication is required")
    return Redis(
        host=os.environ["BULWARK_EXECUTOR_REDIS_HOST"],
        port=int(os.environ.get("BULWARK_EXECUTOR_REDIS_PORT", "6380")),
        username=os.environ["BULWARK_EXECUTOR_REDIS_USERNAME"],
        password=password,
        ssl=True,
        ssl_cert_reqs="required",
        ssl_check_hostname=True,
        ssl_ca_certs=os.environ["BULWARK_EXECUTOR_REDIS_CA_FILE"],
        socket_connect_timeout=1.0,
        socket_timeout=1.0,
        max_connections=16,
        retry=Retry(NoBackoff(), 0),
        retry_on_timeout=False,
    )

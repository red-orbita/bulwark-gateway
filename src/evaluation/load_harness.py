"""Seeded closed-loop input-pipeline load through two in-process ASGI apps.

No sockets, backend URL option, application lifespan, Redis, or service startup.
This is deliberately NOT the production proxy or a sustainable-capacity test.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import random
import resource
import sys
import time
import tracemalloc
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict, Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from src.evaluation.evidence import IncompleteScanError, read_bounded, require_complete_scan, validate_corpus
from src.evaluation.profile_validation import ProfileConfig, build_profile
from src.models import Verdict
from src.scanners.protocol import ScanContext


class LoadConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    requests: int = Field(default=100, ge=1, le=10000)
    concurrency: int = Field(default=4, ge=1, le=32)
    warmup: int = Field(default=5, ge=0, le=100)
    seed: int = Field(default=42, ge=0, le=2**32 - 1)
    backend_delay_ms: float = Field(default=1, ge=0, le=100)
    request_timeout_seconds: float = Field(default=5, gt=0, le=10)
    run_timeout_seconds: float = Field(default=60, gt=0, le=300)


class _RequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=16384)


async def run_load(
    corpus: Path, *, manifest: Path, tuning: Path | None, config: LoadConfig,
    profile: ProfileConfig, model_dir: Path, revision: str, hardware: str,
) -> dict:
    if not revision or not hardware or len(revision) > 128 or len(hardware) > 512:
        raise ValueError("Bounded revision and hardware descriptions required")
    if tracemalloc.is_tracing():
        raise ValueError("Run in a dedicated process without active tracemalloc")
    rows, provenance = await asyncio.to_thread(
        validate_corpus, corpus, manifest_path=manifest, tuning_path=tuning,
    )
    pipeline, readiness = await build_profile(profile, model_dir)
    report = {
        "schema_version": 1, "scope": "hermetic_closed_loop_asgi_input_pipeline_mock_backend",
        "revision_operator_supplied": revision, "hardware_operator_supplied": hardware,
        "corpus": provenance, "readiness": readiness, "load_config": config.model_dump(),
        "load_config_sha256": hashlib.sha256(
            json.dumps(config.model_dump(), sort_keys=True).encode(),
        ).hexdigest(),
        "evidence_valid": False, "production_capacity_established": False,
        "limitations": [
            "Not production proxy: no auth, tenant routing, output/tool filters, SSE, telemetry or network",
            "Closed-loop scheduling excludes queue delay before worker admission (coordinated omission)",
            "Regex uses bounded worker threads; GIL and host contention affect results",
            "Tracemalloc instrumentation is included in latency; memory is process-wide",
            "Warmup excluded from timings; RSS high-water includes imports, warmup and earlier process activity",
            "A short finite run cannot establish sustainable RPS or a latency SLO",
        ],
    }
    if pipeline is None:
        report["status"] = "not_ready"
        return report
    rng = random.Random(config.seed)  # noqa: S311 - seeded workload, never credentials
    schedule = [rng.randrange(len(rows)) for _ in range(config.requests)]
    report["schedule_sha256"] = hashlib.sha256(json.dumps(schedule).encode()).hexdigest()
    report["scheduled_mix"] = {
        label: sum(rows[index]["label"] == label for index in schedule)
        for label in ("benign", "malicious")
    }
    backend_calls = 0

    async def backend(request: Request) -> JSONResponse:
        nonlocal backend_calls
        backend_calls += 1
        await asyncio.sleep(config.backend_delay_ms / 1000)
        return JSONResponse({"choices": [{"message": {"content": "synthetic response"}}]})

    backend_app = Starlette(routes=[Route("/v1/chat/completions", backend, methods=["POST"])])
    latencies: list[float] = []
    verdicts = {label: {"allow": 0, "warn": 0, "block": 0, "redact": 0, "error": 0}
                for label in ("benign", "malicious")}
    next_index = 0
    stop_admission = False
    incomplete_scans = 0

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=backend_app), base_url="http://backend.invalid",
            timeout=config.request_timeout_seconds, trust_env=False, follow_redirects=False,
        ) as backend_client:
            async def gateway(request: Request) -> JSONResponse:
                # Only this process's validated <=16KiB strings can reach the app.
                body = _RequestBody.model_validate_json(await request.body())
                result = await pipeline.run_input_blocking(
                    body.text, ScanContext(tenant_id="evaluation", agent_id="offline-load", request_id="load"),
                )
                require_complete_scan(result.events)
                if result.verdict != Verdict.BLOCK:
                    response = await backend_client.post("/v1/chat/completions", json={"model": "mock"})
                    response.raise_for_status()
                return JSONResponse({"verdict": result.verdict.value},
                                    status_code=403 if result.verdict == Verdict.BLOCK else 200)

            app = Starlette(routes=[Route("/v1/chat/completions", gateway, methods=["POST"])])
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://gateway.invalid",
                timeout=config.request_timeout_seconds, trust_env=False, follow_redirects=False,
            ) as client:
                async def send(index: int) -> str:
                    async with asyncio.timeout(config.request_timeout_seconds):
                        response = await client.post("/v1/chat/completions", json={"text": rows[index]["text"]})
                        return response.json()["verdict"]

                async def worker() -> None:
                    nonlocal next_index, stop_admission, incomplete_scans
                    while next_index < len(schedule) and not stop_admission:
                        index = schedule[next_index]
                        next_index += 1
                        started = time.perf_counter()
                        try:
                            verdict = await send(index)
                        except IncompleteScanError:
                            incomplete_scans += 1
                            verdict = "error"
                            stop_admission = True
                        except (TimeoutError, httpx.HTTPError, ValueError, RuntimeError):
                            verdict = "error"
                            # Timed-out native/thread work may still run. Stop
                            # admission so cancelled work cannot grow a queue.
                            stop_admission = True
                        latencies.append((time.perf_counter() - started) * 1000)
                        verdicts[rows[index]["label"]][verdict] += 1

                try:
                    async with asyncio.timeout(config.run_timeout_seconds):
                        for index in range(config.warmup):
                            await send(index % len(rows))
                except IncompleteScanError:
                    report.update(status="warmup_failed", incomplete_scans=1)
                    return report
                except (TimeoutError, httpx.HTTPError, ValueError, RuntimeError):
                    report["status"] = "warmup_failed"
                    return report
                backend_calls = 0
                tracemalloc.start()
                cpu_start = time.process_time()
                wall_start = time.perf_counter()
                timed_out = False
                try:
                    async with asyncio.timeout(config.run_timeout_seconds):
                        async with asyncio.TaskGroup() as group:
                            for _ in range(min(config.concurrency, config.requests)):
                                group.create_task(worker())
                except TimeoutError:
                    timed_out = True
                finally:
                    wall = time.perf_counter() - wall_start
                    cpu = time.process_time() - cpu_start
                    _, peak = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
        ordered = sorted(latencies)
        scanner_errors = sum(item["metrics"]["total_errors"] for item in pipeline.list_scanners())
        request_errors = sum(counts["error"] for counts in verdicts.values())
        valid = not timed_out and not scanner_errors and not request_errors and len(latencies) == config.requests
        report.update(
            status="measured" if valid else "incomplete_or_error", evidence_valid=valid,
            completed=len(latencies), unfinished=config.requests - len(latencies),
            request_errors=request_errors, scanner_errors=scanner_errors,
            incomplete_scans=incomplete_scans,
            wall_seconds=wall, process_cpu_seconds=cpu,
            process_cpu_percent_one_core=100 * cpu / wall,
            completions_per_second=len(latencies) / wall,
            successful_completions_per_second=(len(latencies) - request_errors) / wall,
            p95_ms=ordered[math.ceil(len(ordered) * .95) - 1] if ordered else None,
            latency_scope="admitted_request_including_asgi_scan_mock_delay_and_errors",
            python_traced_peak_bytes=peak,
            process_lifetime_peak_rss_bytes=(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
                                             if sys.platform == "linux" else None),
            verdicts=verdicts, backend_calls=backend_calls,
        )
        return report
    finally:
        await pipeline.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tuning", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--profile-config", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, default=Path("models"))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--hardware", required=True)
    args = parser.parse_args()
    try:
        config = LoadConfig.model_validate_json(read_bounded(args.config, 16384))
        profile = ProfileConfig.model_validate_json(read_bounded(args.profile_config, 16384))
        report = asyncio.run(run_load(
            args.corpus, manifest=args.manifest, tuning=args.tuning, config=config,
            profile=profile, model_dir=args.model_dir, revision=args.revision, hardware=args.hardware,
        ))
    except (OSError, ValueError):
        report = {"status": "invalid_inputs", "evidence_valid": False}
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["evidence_valid"] else 2)


if __name__ == "__main__":
    main()

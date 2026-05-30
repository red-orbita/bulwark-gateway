# skill: performance-hardening

## description
Profiling del hot path, optimización de regex, cacheo agresivo, tuning de Uvicorn/httpx, y verificación de latencia p50/p95 < 50ms (excluyendo backend). Se usa cuando se detectan latencias altas, antes de escalar a producción, o cuando se añaden patrones nuevos al pipeline.

## triggers
- Hot path medido > 50ms p95 (excluyendo latencia del backend)
- Se añaden > 10 patrones regex nuevos al input guardrail
- Se prepara deploy a producción con SLA de latencia
- Se incrementa el número de IOCs > 10,000 entries
- Se añade un nuevo middleware al pipeline

## context
- Stack: Python 3.11+, FastAPI, Uvicorn, httpx.AsyncClient, Pydantic v2
- Threat model: usuario no trusted, fail-closed, hot path <50ms p95
- Dependencias: `policy.yaml`, `iocs.json`, `sentinel_preflight.py`, middleware HTTP
- Restricciones: NO usar LLM para validación en hot path. Solo regex compiladas, caché, reglas deterministas.

## steps
1. **Benchmark baseline**:
   - Crear script `scripts/benchmark.py`:
     ```python
     import time, statistics
     from src.guardrails.input_guardrail import InputGuardrail
     from src.guardrails.output_filter import OutputFilter
     from src.guardrails.tool_policy import ToolPolicyEngine
     
     guardrail = InputGuardrail()
     samples = []
     test_input = "Search our internal docs for Python production deployment best practices"
     
     for _ in range(10000):
         start = time.perf_counter_ns()
         guardrail.inspect(test_input)
         samples.append((time.perf_counter_ns() - start) / 1_000_000)  # ms
     
     print(f"p50: {statistics.median(samples):.3f}ms")
     print(f"p95: {sorted(samples)[int(len(samples)*0.95)]:.3f}ms")
     print(f"p99: {sorted(samples)[int(len(samples)*0.99)]:.3f}ms")
     ```
   - Ejecutar: `python scripts/benchmark.py`
   - Target: input_guardrail < 5ms p95, output_filter < 3ms p95, tool_policy < 1ms p95

2. **Regex optimization**:
   - Verificar que TODAS las regex usan `re.compile()` a nivel de módulo (no por request):
     ```bash
     grep -n "re.compile" src/guardrails/input_guardrail.py | head -5
     # Debe estar en scope de módulo, NO dentro de funciones
     ```
   - Buscar regex costosas (backtracking):
     - Evitar `.*` seguido de alternaciones: `r"ignore.*previous|prior"` → usar alternación directa
     - Evitar nested quantifiers: `(a+)+` → catastrófico
   - Si hay > 20 patterns, considerar combinarlos en una sola regex alternada:
     ```python
     COMBINED = re.compile("|".join(p.regex.pattern for p in PATTERNS), re.I)
     # Pre-screen con COMBINED, luego match individual para categorizar
     ```
   - Medir ganancia: re-run benchmark

3. **IOC lookup optimization**:
   - Si IOC count > 10,000: verificar que usa `set()` (O(1) lookup, no list)
   - Para domain matching con subdominios: considerar trie o suffix set:
     ```python
     # Actual: O(n) check por subdominio
     # Optimizado: frozenset + precomputed suffixes
     self.domain_suffixes = frozenset(d for d in domains for _ in [d])
     ```
   - `check_content()`: si se llama con textos largos, pre-extraer URLs/IPs con una sola regex pass (no múltiples findall)

4. **Cacheo**:
   - Policy lookups: usar `@lru_cache` o `dict` directo (ya implementado como dict)
   - Input guardrail: NO cachear (cada input es único, cache miss rate ~100%)
   - IOC check: NO cachear (input-dependent)
   - Rate limit buckets: ya O(1) por diseño
   - Considerar cache de policy engine result por `(tenant_id, agent_id)` → ya O(1) dict lookup

5. **Uvicorn tuning**:
   - Workers: `min(2 * CPU_COUNT + 1, 8)` — no más de 8 para el proxy
   - Verificar `--limit-concurrency` para prevenir queue buildup
   - Verificar `--backlog` (default 2048, suficiente para la mayoría)
   - HTTP/1.1 keepalive: habilitar con `--timeout-keep-alive 5`
   - Verificar que access_log está deshabilitado (ya está: `access_log=False`)

6. **httpx tuning**:
   - Usar connection pool persistente (no crear AsyncClient por request):
     ```python
     # En app.state durante lifespan:
     app.state.http_client = httpx.AsyncClient(
         timeout=settings.backend_timeout,
         limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
         http2=True,  # If backend supports it
     )
     ```
   - Verificar que no se instancia `AsyncClient()` dentro de route handlers
   - Configurar `limits.max_connections` basado en expected RPS

7. **Async parallelization**:
   - Input guardrail + IOC check pueden ejecutarse en paralelo:
     ```python
     input_result, ioc_matches = await asyncio.gather(
         asyncio.to_thread(input_guardrail.inspect_messages, messages),
         asyncio.to_thread(ioc_manager.check_content, content),
     )
     ```
   - Solo si benchmark muestra que la serialización es bottleneck (probablemente no para <5ms)

8. **Final benchmark**:
   - Re-ejecutar `scripts/benchmark.py` con optimizaciones aplicadas
   - Ejecutar load test: `wrk -t4 -c100 -d10s http://localhost:8080/v1/chat/completions`
   - Documentar mejora en `docs/performance.md`

## validation
- `scripts/benchmark.py` muestra: input_guardrail p95 < 5ms, completo pipeline p95 < 50ms
- `pytest -v` — 0 fallos (optimizaciones no cambian comportamiento)
- `grep -n "AsyncClient()" src/routes/` — máximo 0 instanciaciones por request (usar pool)
- `grep -n "re.compile" src/guardrails/` — todas las compilaciones en scope de módulo
- Load test: p95 < 50ms con 100 concurrent connections (excluyendo backend latency)
- No hay `time.sleep`, `open()`, ni I/O síncrono en hot path

## constraints
- Las optimizaciones NUNCA reducen cobertura de detección (no eliminar patrones por rendimiento)
- Si combinar regex reduce la capacidad de categorizar threats: mantener patterns individuales
- El connection pool httpx DEBE tener limits configurados (prevenir connection exhaustion)
- Las optimizaciones DEBEN medirse con benchmark antes/después (no cambios especulativos)
- Fail-closed se mantiene: si una optimización puede causar fail-open en edge cases, descartarla
- NO usar C extensions o Cython sin justificación de benchmark (mantener deployability simple)

## outputs
- `scripts/benchmark.py` — Script de benchmark reproducible
- `docs/performance.md` — Resultados antes/después, configuración de tuning
- Modificaciones a `src/main.py` — httpx pool en lifespan
- Modificaciones a `src/guardrails/input_guardrail.py` — regex optimizadas si aplica
- Actualización a Uvicorn config en `src/main.py` o `docker-compose.yaml`

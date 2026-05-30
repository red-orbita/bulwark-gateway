# skill: security-architecture

## description
Diseñar o revisar la arquitectura del guardrail proxy, definiendo separación de capas (middleware → tool-gate → output filter), trade-offs latencia vs profundidad de inspección, y criterios de evolución. Se usa cuando se añade un componente nuevo al pipeline o se reestructura el flujo de request.

## triggers
- Se propone añadir un nuevo middleware o capa de inspección al pipeline
- Se detecta que el hot path supera 50ms p95
- Se cambia el modo de operación (proxy ↔ sidecar) o se añade streaming

## context
- Stack: Python 3.11+, FastAPI, Uvicorn, httpx.AsyncClient, Pydantic v2
- Threat model: usuario no trusted, fail-closed, hot path <50ms p95
- Dependencias: `policy.yaml`, `iocs.json`, `sentinel_preflight.py`, middleware HTTP
- Restricciones: NO usar LLM para validación en hot path. Solo regex compiladas, caché, reglas deterministas.

## steps
1. Generar diagrama ASCII del pipeline actual leyendo `src/main.py`, `src/routes/proxy.py`, y `src/middleware/`:
   ```
   Request → Auth → RateLimit → InputGuardrail → IOC → [Backend] → ToolPolicy → OutputFilter → Response
   ```
2. Identificar componentes en hot path vs cold path:
   - Hot path: todo lo que ejecuta POR REQUEST (auth, rate limit, input guardrail, IOC check, tool policy, output filter)
   - Cold path: policy reload, IOC update, admin endpoints
3. Para cada componente en hot path, documentar:
   - Latencia medida o estimada (regex ~1ms, IOC lookup ~0.5ms, httpx backend ~50-500ms)
   - Modo de fallo (fail-closed: bloquea; fail-open: permite)
   - Estado mutable (rate limit bucket, IOC set)
4. Evaluar trade-offs de la propuesta de cambio:
   - ¿Añade latencia al hot path? → Cuantificar con benchmark
   - ¿Rompe fail-closed si falla? → Definir fallback
   - ¿Requiere I/O en hot path? → Mover a caché precalculada
5. Generar propuesta de arquitectura actualizada con diagrama, escribir en `docs/architecture.md`
6. Si se detecta que hot path > 50ms sin contar backend:
   - Proponer paralelización (input guardrail + IOC check en paralelo con asyncio.gather)
   - Proponer compilación de regex a nivel de módulo (no por request)
   - Proponer LRU cache para policy lookups
7. Rollback: si el cambio arquitectural rompe tests, revertir con `git checkout -- src/`

## validation
- `pytest -v` — todos los tests pasan
- Benchmark manual: `time curl -X POST http://localhost:8080/v1/chat/completions -d '{...}'` — p95 < 50ms (excluyendo backend)
- Verificar fail-closed: matar el backend → la respuesta debe ser 502, NO 200 con datos sin filtrar
- Diagrama en `docs/architecture.md` debe reflejar el código real (no aspiracional)

## constraints
- El hot path NUNCA hace I/O a disco por request (IOCs y policies se cargan en memoria al startup/reload)
- Ningún componente del pipeline puede ser async-blocking (no `time.sleep`, no sync I/O)
- Si un componente falla con excepción, el request se BLOQUEA (no se permite pasar sin inspección)
- El backend httpx call es el ÚNICO componente con latencia variable aceptable (controlado por timeout)
- No se añaden dependencias externas al hot path sin benchmark previo

## outputs
- `docs/architecture.md` — Diagrama actualizado + tabla de latencias + trade-offs
- Modificaciones a `src/main.py` o `src/routes/proxy.py` si se reestructura el pipeline
- Issue/TODO documentado si se detectan mejoras no implementadas inmediatamente

# skill: secure-design-review

## description
Revisión estática de seguridad del código FastAPI: validación Pydantic, manejo de streaming, timeouts httpx, exposición de endpoints, inyección de dependencias, y ausencia de operaciones síncronas en hot path. Se usa antes de merge a main o cuando se modifica un endpoint/middleware.

## triggers
- Se modifica cualquier archivo en `src/routes/` o `src/middleware/`
- Se añade un nuevo endpoint
- Se modifica el proxy flow en `src/routes/proxy.py`
- Pre-merge review de cualquier PR con cambios en `src/`

## context
- Stack: Python 3.11+, FastAPI, Uvicorn, httpx.AsyncClient, Pydantic v2
- Threat model: usuario no trusted, fail-closed, hot path <50ms p95
- Dependencias: `policy.yaml`, `iocs.json`, `sentinel_preflight.py`, middleware HTTP
- Restricciones: NO usar LLM para validación en hot path. Solo regex compiladas, caché, reglas deterministas.

## steps
1. **Pydantic v2 validation**:
   - Verificar que TODOS los request bodies usan modelos Pydantic (no `await request.json()` sin validar)
   - Buscar `request.json()` directo → reemplazar por `ChatRequest(**body)` con try/except ValidationError
   - Verificar que ningún modelo usa `model_config = {"extra": "allow"}` (rechazar campos inesperados)
   - Comprobar que `str` fields tienen `max_length` donde aplique
2. **httpx security**:
   - Verificar timeout explícito en TODOS los `httpx.AsyncClient()` calls
   - Comprobar `follow_redirects=False` (default) — no seguir redirects del backend
   - Verificar que no se pasan headers del usuario al backend sin sanitizar
   - Buscar SSRF: ¿el usuario puede controlar la URL de destino? → BLOQUEAR
3. **Streaming (SSE)**:
   - Si existe `StreamingResponse`: verificar que el output filter inspecciona CADA chunk
   - Verificar que un chunk parcial no puede bypassear detección (buffering de tokens)
   - Comprobar timeout en el stream (no mantener conexión indefinida)
4. **Endpoints exposure**:
   - `/docs` y `/redoc` DEBEN estar deshabilitados en producción (`docs_url=None` si not debug)
   - `/admin/*` endpoints DEBEN requerir autenticación elevada (no solo el token de tenant)
   - No exponer stack traces en respuestas de error (verificar exception handlers)
5. **Async safety**:
   - Buscar `time.sleep()` → reemplazar por `asyncio.sleep()` o eliminar
   - Buscar I/O síncrono: `open()`, `json.load()` en handlers → mover a startup/background
   - Verificar que regex compiladas son a nivel de módulo (no recompiladas por request)
   - Buscar `threading.Lock` → verificar si debería ser `asyncio.Lock`
6. **Auth bypass check**:
   - Verificar que TODAS las rutas (excepto /health, /ready) pasan por AuthMiddleware
   - Comprobar que no hay rutas registradas DESPUÉS del middleware (order matters)
   - Verificar que token validation no tiene timing side-channel (constant-time compare)
7. **Error handling**:
   - Verificar que excepciones internas devuelven 500 genérico (no leak info del sistema)
   - Comprobar que ValidationError devuelve 422 sin exponer estructura interna
   - Verificar que httpx.ConnectError → 502, httpx.TimeoutException → 504
8. Documentar hallazgos en `docs/security-review.md` con fecha y status (fixed/open/accepted)
9. Rollback: si los fixes rompen tests → `git stash` y reportar como issue

## validation
- `pytest -v` — 0 fallos
- `ruff check src/ --select S` — 0 findings de seguridad (bandit rules)
- `grep -rn "request.json()" src/routes/` — 0 usos sin validación Pydantic posterior
- `grep -rn "time.sleep" src/` — 0 resultados
- `grep -rn "open(" src/routes/ src/middleware/` — 0 resultados (no I/O síncrono en handlers)
- Verificar manualmente: `curl http://localhost:8080/docs` devuelve 404 con `SENTINEL_DEBUG=false`
- Verificar: request sin Authorization → 401 en todos los endpoints excepto health

## constraints
- NUNCA exponer mensajes de error internos (paths, stack traces, config values) al usuario
- NUNCA confiar en headers del usuario sin validación (X-Tenant-ID podría ser forged → validar contra JWT claims)
- NUNCA usar `eval()`, `exec()`, `importlib.import_module()` con input del usuario
- El proxy NUNCA sigue redirects del backend (previene SSRF via redirect)
- Streaming responses DEBEN ser inspeccionadas — no es aceptable bypassear output filter por rendimiento
- Todo hallazgo con severidad >= high DEBE ser corregido antes de merge

## outputs
- `docs/security-review.md` — Checklist con hallazgos, severidad, y status
- Fixes directos en `src/` para hallazgos critical/high
- Issues documentados para hallazgos medium/low no corregidos inmediatamente
- Actualización de tests si se descubren paths no cubiertos

# skill: compliance-audit

## description
Validar cumplimiento contra OWASP LLM Top 10, GDPR (Art. 22 — decisiones automatizadas), SOC2 CC6.1 (acceso lógico), audit logging sin PII, y retención de métricas. Se usa en auditorías periódicas, antes de certificaciones, o cuando se añade manejo de datos personales.

## triggers
- Preparación para auditoría SOC2/ISO 27001
- Se añade un nuevo campo que podría contener PII al log de audit
- Cambio en política de retención de datos
- Nuevo tenant con requisitos regulatorios específicos (GDPR, HIPAA, PCI)
- Revisión trimestral de compliance

## context
- Stack: Python 3.11+, FastAPI, Uvicorn, httpx.AsyncClient, Pydantic v2
- Threat model: usuario no trusted, fail-closed, hot path <50ms p95
- Dependencias: `policy.yaml`, `iocs.json`, `sentinel_preflight.py`, middleware HTTP
- Restricciones: NO usar LLM para validación en hot path. Solo regex compiladas, caché, reglas deterministas.

## steps
1. **OWASP LLM Top 10 Mapping**:
   - Para cada item (LLM01-LLM10), verificar que existe un control implementado:
     ```
     LLM01 Prompt Injection    → src/guardrails/input_guardrail.py    [CONTROL]
     LLM02 Insecure Output     → src/guardrails/output_filter.py      [CONTROL]
     LLM04 Model DoS           → src/middleware/rate_limit.py          [CONTROL]
     LLM06 Sensitive Info      → src/guardrails/output_filter.py      [CONTROL]
     LLM07 Insecure Plugin     → src/guardrails/tool_policy.py        [CONTROL]
     LLM08 Excessive Agency    → src/guardrails/tool_policy.py        [CONTROL]
     ```
   - Documentar items sin control directo: LLM03, LLM05, LLM09, LLM10 → marcar como N/A o riesgo aceptado con justificación
   - Generar tabla de cobertura con porcentaje

2. **GDPR Art. 22 — Decisiones automatizadas**:
   - Verificar que cuando el proxy BLOQUEA un request, el usuario recibe:
     - Motivo genérico del bloqueo (sin exponer reglas internas)
     - Mecanismo de apelación (contacto humano)
   - Verificar que NO se toman decisiones basadas en profiling sin consentimiento
   - Verificar `right to explanation`: el log tiene suficiente info para explicar POR QUÉ se bloqueó
   - Comprobar respuestas 403: `grep "security_violation" src/routes/proxy.py` → debe incluir campo `code`

3. **SOC2 CC6.1 — Acceso lógico**:
   - Verificar autenticación en TODOS los endpoints no públicos
   - Verificar separación de tenants (un tenant NO puede ver/afectar datos de otro)
   - Verificar que admin endpoints tienen auth separada/elevada
   - Comprobar que tokens tienen expiración (JWT `exp` claim)
   - Verificar rotación de API keys documentada

4. **Audit Logging sin PII**:
   - Revisar `SecurityEvent` model: verificar que NO se logea:
     - Contenido completo del mensaje del usuario (solo `matched_pattern` truncado)
     - IP del usuario sin hashing
     - Tokens/credentials en claro
   - Verificar que SÍ se logea:
     - `tenant_id`, `agent_id`, `timestamp`, `verdict`, `category`, `severity`
     - `tool_name` (si aplica), `request_id`
   - Ejecutar: `grep -rn "content" src/ | grep -i log` → verificar que no se logea message content completo
   - Verificar formato estructurado (JSON Lines) para ingestión SIEM

5. **Retención de métricas**:
   - Documentar política de retención:
     - Security events: ≥ 90 días (obligatorio para forensia)
     - Rate limit counters: en memoria (no persistido)
     - Request/response bodies: NUNCA almacenados
   - Verificar que no hay escritura a disco de request bodies en el código
   - Si se usa Redis: verificar TTL en keys (`EXPIRE` configurado)

6. **Redacción automática**:
   - Verificar que `output_filter.py` redacta ANTES de:
     - Devolver al usuario
     - Escribir en logs
   - Comprobar que los patterns de redacción cubren: AWS keys, DB URLs, private keys, JWT secrets, CC, SSN
   - Test: enviar request que produce respuesta con secret → verificar que el log NO contiene el secret

7. Generar reporte en `docs/compliance-report.md`:
   ```markdown
   # Compliance Report — <fecha>
   ## OWASP LLM Top 10: X/10 cubiertos
   ## GDPR Art. 22: [PASS/FAIL]
   ## SOC2 CC6.1: [PASS/FAIL]
   ## Audit Logging: [PASS/FAIL]
   ## Data Retention: [PASS/FAIL]
   ## Findings: <N> (critical: X, high: Y, medium: Z)
   ```

## validation
- `docs/compliance-report.md` existe con fecha actual
- OWASP LLM coverage ≥ 6/10 items con control implementado
- `grep -rn "content.*log\|log.*content" src/` — 0 resultados de logging de message content
- Todos los endpoints (excepto /health, /ready) devuelven 401 sin token
- Response 403 incluye campo `code` para trazabilidad
- `pytest -v` pasa (los tests validan que no se expone info interna en errors)
- No existe `request.body` ni `response.body` almacenado en disco/DB en ningún path

## constraints
- NUNCA logear el contenido completo del mensaje del usuario (solo metadata + pattern matched)
- NUNCA almacenar request/response bodies en disco, DB, o caché persistente
- Los security events DEBEN retener ≥ 90 días para cumplir SOC2 audit trail
- Las respuestas de bloqueo (403) DEBEN ser genéricas — NO revelar qué regex o regla específica se activó
- El campo `matched_pattern` en logs se TRUNCA a 200 chars y NO contiene el mensaje completo
- Si un finding es critical y no se puede remediar inmediatamente: documentar plan de acción con fecha límite

## outputs
- `docs/compliance-report.md` — Reporte completo con fecha y coverage
- Fixes en `src/routes/proxy.py` si se detectan leaks de info en error responses
- Fixes en logging si se detecta PII en audit events
- Actualización a `src/models.py` si SecurityEvent necesita campos adicionales para compliance
- Issues para findings no remediados inmediatamente

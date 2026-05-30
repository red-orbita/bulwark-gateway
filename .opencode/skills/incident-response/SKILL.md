# skill: incident-response

## description
Flujo de contención post-incidente: análisis de logs estructurados, bloqueo inmediato de IOCs, hot-reload de reglas sin downtime, y forensia rápida. Se usa cuando se detecta un bypass, un ataque exitoso, o un patrón anómalo en los logs de seguridad.

## triggers
- Alerta de security_event con verdict=BLOCK y category=credential_access o reverse_shell en producción
- Detección de patrón de jailbreak exitoso (agente ejecutó tool bloqueado)
- Reporte externo de vulnerabilidad o bypass
- Spike anómalo en rate limit hits de un tenant

## context
- Stack: Python 3.11+, FastAPI, Uvicorn, httpx.AsyncClient, Pydantic v2
- Threat model: usuario no trusted, fail-closed, hot path <50ms p95
- Dependencias: `policy.yaml`, `iocs.json`, `sentinel_preflight.py`, middleware HTTP
- Restricciones: NO usar LLM para validación en hot path. Solo regex compiladas, caché, reglas deterministas.

## steps
1. **CONTENCIÓN INMEDIATA (<5 min)**:
   - Identificar tenant_id y agent_id del incidente en logs:
     ```bash
     grep '"category":"credential_access"' /var/log/sentinel/audit.jsonl | tail -20
     ```
   - Si el ataque está en curso: bloquear tenant temporalmente añadiendo a denied list:
     ```bash
     # Añadir IOC de emergencia
     python3 -c "
     import json
     iocs = json.load(open('config/iocs.json'))
     iocs['domains'].append('<dominio_atacante>')
     json.dump(iocs, open('config/iocs.json', 'w'), indent=2)
     "
     # Hot-reload sin restart
     curl -X POST http://localhost:8080/admin/policies/reload
     ```
   - Si el bypass fue via tool_call: añadir tool a denied_tools en la policy del tenant afectado
   - Verificar contención: repetir el ataque desde logs → debe devolver 403

2. **ANÁLISIS FORENSE (5-30 min)**:
   - Extraer timeline completa del tenant afectado:
     ```bash
     grep '"tenant_id":"<tenant>"' /var/log/sentinel/audit.jsonl | jq -s 'sort_by(.timestamp)'
     ```
   - Identificar el vector de bypass:
     - ¿Regex no cubría el patrón? → Documentar payload exacto
     - ¿Policy mal configurada? → Documentar configuración incorrecta
     - ¿Race condition en rate limiter? → Documentar timing
   - Determinar alcance: ¿qué datos/tools accedió el atacante post-bypass?
   - Extraer payload para regresión:
     ```bash
     grep '"matched_pattern"' /var/log/sentinel/audit.jsonl | grep '<tenant>' | jq '.matched_pattern'
     ```

3. **REMEDIACIÓN (30 min - 2h)**:
   - Añadir nuevo patrón de detección en `src/guardrails/input_guardrail.py`:
     ```python
     Pattern(
         re.compile(r"<regex_del_bypass>", re.I),
         ThreatCategory.<CATEGORY>,
         "critical",
         "<descripción del vector>",
     )
     ```
   - Escribir test de regresión con el payload exacto del incidente:
     ```python
     def test_incident_<YYYYMMDD>_<descripcion>(self, guardrail):
         result = guardrail.inspect("<payload exacto del ataque>")
         assert result.verdict == Verdict.BLOCK
     ```
   - Ejecutar suite completa: `pytest -v`
   - Si el bypass fue en tool_policy: reforzar la policy con denied_arguments más específicos
   - Si fue IOC miss: actualizar `config/iocs.json` y ejecutar `scripts/update_iocs.sh`

4. **DEPLOY Y VERIFICACIÓN**:
   - Commit: `git add -A && git commit -m "fix(security): block <vector> — incident <date>"`
   - Deploy: según pipeline (push to branch → CI → deploy)
   - Verificar en producción: curl con el payload debe devolver 403
   - Hot-reload policies si solo cambió config: `curl -X POST .../admin/policies/reload`

5. **POST-MORTEM**:
   - Documentar en `docs/incidents/<YYYY-MM-DD>-<slug>.md`:
     - Timeline (detección → contención → remediación)
     - Root cause
     - Impacto (qué se expuso, a quién)
     - Acciones preventivas
   - Actualizar `docs/threat-model.md` con el nuevo vector
   - Revisar si otros tenants podrían ser afectados por el mismo vector

## validation
- El payload del incidente ahora devuelve 403 (no 200)
- `pytest -v` — 0 fallos, incluyendo nuevo test de regresión
- Log de audit muestra el bloqueo del payload con el nuevo patrón
- Hot-reload funciona: `curl /admin/policies/reload` → 200, luego el payload se bloquea
- No hay regresiones: payloads legítimos siguen pasando (verificar con tests negativos)

## constraints
- La contención NUNCA espera a la remediación completa — bloquear primero, investigar después
- Los logs forenses NUNCA contienen PII del usuario (solo tenant_id, agent_id, pattern matched)
- El hot-reload NUNCA requiere restart del servicio (zero-downtime obligatorio)
- Los tests de regresión de incidentes NUNCA se eliminan (sirven como garantía permanente)
- Si el bypass afecta fail-closed: escalar inmediatamente (el proxy podría estar dejando pasar todo)
- NO notificar al atacante que fue detectado (respuestas genéricas 403, sin detalles del bloqueo)

## outputs
- `config/iocs.json` — IOCs de emergencia añadidos
- `config/policies/<tenant>.yaml` — Policy reforzada
- `src/guardrails/input_guardrail.py` — Nuevo patrón de detección
- `tests/test_input_guardrail.py` — Test de regresión del incidente
- `docs/incidents/<YYYY-MM-DD>-<slug>.md` — Post-mortem
- `docs/threat-model.md` — Actualizado con nuevo vector

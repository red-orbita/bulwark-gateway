# skill: threat-modeling

## description
Actualizar la matriz de amenazas del proyecto ante nuevos vectores de ataque (OWASP LLM Top 10, jailbreaks evolutivos, cross-agent injection, tool-call smuggling). Se usa cuando se descubre un nuevo vector, se publica investigación relevante, o se añade un endpoint/tool nuevo al proxy.

## triggers
- Se publica un nuevo CVE o paper sobre ataques a agentes LLM
- Se añade un nuevo endpoint o tool al proxy
- Se detecta un bypass en las reglas existentes (falso negativo en producción)
- Revisión periódica (mensual)

## context
- Stack: Python 3.11+, FastAPI, Uvicorn, httpx.AsyncClient, Pydantic v2
- Threat model: usuario no trusted, fail-closed, hot path <50ms p95
- Dependencias: `policy.yaml`, `iocs.json`, `sentinel_preflight.py`, middleware HTTP
- Restricciones: NO usar LLM para validación en hot path. Solo regex compiladas, caché, reglas deterministas.

## steps
1. Leer la matriz actual en `docs/threat-model.md` (crear si no existe)
2. Mapear el nuevo vector contra STRIDE:
   - **S**poofing: ¿El usuario puede suplantar otro tenant/agent?
   - **T**ampering: ¿Puede modificar policies/IOCs en runtime?
   - **R**epudiation: ¿Puede actuar sin dejar log?
   - **I**nformation Disclosure: ¿Puede extraer secrets del sistema?
   - **D**enial of Service: ¿Puede agotar recursos del proxy?
   - **E**levation of Privilege: ¿Puede escalar de un sandbox_level a otro?
3. Mapear contra OWASP LLM Top 10 (2025):
   - LLM01: Prompt Injection → input_guardrail.py
   - LLM02: Insecure Output Handling → output_filter.py
   - LLM03: Training Data Poisoning → N/A (no entrenamos)
   - LLM04: Model Denial of Service → rate_limit.py
   - LLM05: Supply Chain → IOC feeds, skill validation
   - LLM06: Sensitive Information Disclosure → output_filter.py
   - LLM07: Insecure Plugin Design → tool_policy.py
   - LLM08: Excessive Agency → tool_policy.py (max_tool_calls, denied_tools)
   - LLM09: Overreliance → N/A (proxy, no genera)
   - LLM10: Model Theft → N/A (no servimos modelo)
4. Para cada vector nuevo:
   - Documentar: descripción, ejemplo concreto de exploit, impacto (C/I/A), probabilidad
   - Asignar control existente o crear TODO para nuevo control
   - Clasificar riesgo residual: aceptado | mitigado | transferido
5. Identificar vectores residuales NO cubiertos:
   - Multi-turn escalation (estado conversacional)
   - Encoding bypasses no cubiertos por regex actual
   - Cross-tenant data leakage via shared cache
   - Timing side-channels en rate limiter
6. Escribir/actualizar `docs/threat-model.md` con formato tabular
7. Crear issues para controles faltantes con prioridad basada en riesgo

## validation
- `docs/threat-model.md` existe y tiene fecha de última actualización
- Cada vector tiene: descripción, control, riesgo residual
- Los 10 items de OWASP LLM están mapeados a componentes del código
- No hay vectores con impacto "critical" sin control asignado
- `grep -c "TODO" docs/threat-model.md` < 5 (máximo 5 items pendientes)

## constraints
- La matriz NUNCA minimiza un riesgo sin justificación técnica documentada
- Vectores con impacto critical + probabilidad alta requieren control implementado (no solo documentado)
- No se aceptan riesgos residuales en: exfiltración de credentials, ejecución remota de código, bypass de autenticación
- Cada entrada debe ser reproducible: incluir ejemplo de payload o referencia a PoC
- El threat model es un documento vivo: debe tener campo `last_updated` y `reviewed_by`

## outputs
- `docs/threat-model.md` — Matriz STRIDE + OWASP LLM completa
- Issues/TODOs en código para controles faltantes
- Actualizaciones a `src/guardrails/input_guardrail.py` si se identifican patrones nuevos
- Actualización a `config/iocs.json` si se identifican dominios/IPs nuevos

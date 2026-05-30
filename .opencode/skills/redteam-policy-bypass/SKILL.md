# skill: redteam-policy-bypass

## description
Intentar eludir el sistema RBAC: escalada de privilegios entre sandbox levels, tenant hopping via header manipulation, replay de tokens, manipulación de JWT claims, y acceso a admin endpoints sin autorización. Valida que la autenticación, autorización y aislamiento de tenants son robustos.

## triggers
- Después de cambios en `src/middleware/auth.py`
- Cuando se añade un nuevo endpoint o role
- Pre-release con cambios en el sistema de policies
- Después de un incidente de acceso no autorizado

## context
- Target: Guardrail proxy FastAPI (Python 3.11+, httpx, Pydantic v2)
- Mode: TESTING ONLY — usar header `X-Redteam-Mode: true` para bypass de rate-limiting y logging diferenciado
- Scope: Solo endpoints definidos en `policy.yaml`. NO atacar infraestructura externa.
- Safety: Todos los payloads deben ser generados sintéticamente. NO usar datos reales de usuarios.

## steps
1. **Preparar entorno**:
   - Crear dos tenants de testing con policies diferentes:
     - `redteam-restricted`: solo `web_search`, sin command execution
     - `redteam-privileged`: todos los tools, con command execution
   - Obtener tokens válidos para ambos tenants

2. **Categoría 1: Tenant hopping via headers**:
   ```python
   TENANT_HOP_ATTACKS = [
       # Usar token de restricted pero header de privileged
       {"auth": "token_restricted", "headers": {"X-Tenant-ID": "redteam-privileged"}},
       # Header injection vía newline
       {"auth": "token_restricted", "headers": {"X-Tenant-ID": "restricted\r\nX-Tenant-ID: privileged"}},
       # Unicode confusables
       {"auth": "token_restricted", "headers": {"X-Tenant-ID": "redteam-prïvileged"}},
       # Case manipulation
       {"auth": "token_restricted", "headers": {"X-Tenant-ID": "REDTEAM-PRIVILEGED"}},
       # Empty tenant (fallback to default?)
       {"auth": "token_restricted", "headers": {"X-Tenant-ID": ""}},
       {"auth": "token_restricted", "headers": {}},  # No X-Tenant-ID header
   ]
   ```
   - Verificar: el tenant efectivo SIEMPRE viene del JWT, NO del header (si JWT present)

3. **Categoría 2: JWT manipulation**:
   ```python
   JWT_ATTACKS = [
       # Algoritmo none
       {"header": {"alg": "none"}, "payload": {"tenant_id": "admin", "agent_id": "root"}},
       # Cambiar alg de HS256 a RS256 (key confusion)
       {"header": {"alg": "RS256"}, "payload": {"tenant_id": "privileged"}},
       # Token expirado
       {"payload": {"exp": 0, "tenant_id": "privileged"}},
       # Token sin firma
       "eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnRfaWQiOiJhZG1pbiJ9.",
       # Token con claims extra
       {"payload": {"tenant_id": "restricted", "is_admin": True, "role": "superuser"}},
   ]
   ```

4. **Categoría 3: Admin endpoint access**:
   ```python
   ADMIN_ATTACKS = [
       # Acceder a admin sin auth
       {"method": "POST", "path": "/admin/policies/reload", "auth": None},
       {"method": "GET", "path": "/admin/policies", "auth": None},
       {"method": "GET", "path": "/admin/iocs/stats", "auth": None},
       # Acceder con token de tenant normal (no admin)
       {"method": "POST", "path": "/admin/policies/reload", "auth": "token_restricted"},
       # Path traversal en admin
       {"method": "GET", "path": "/admin/../v1/chat/completions", "auth": None},
       # HTTP method override
       {"method": "GET", "path": "/admin/policies/reload", "headers": {"X-HTTP-Method-Override": "POST"}},
   ]
   ```

5. **Categoría 4: Escalada de sandbox**:
   ```python
   ESCALATION_ATTACKS = [
       # Tenant restricted intenta usar run_command (debería estar bloqueado)
       {"tenant": "redteam-restricted", "tool": "run_command", "args": {"command": "id"}},
       # Tenant restricted intenta write_file
       {"tenant": "redteam-restricted", "tool": "write_file", "args": {"filepath": "/tmp/test"}},
       # Intentar max_tool_calls bypass enviando tools en paralelo
       {"tenant": "redteam-restricted", "tools": [{"name": "web_search"}] * 100},
   ]
   ```

6. **Categoría 5: Replay attacks**:
   ```python
   REPLAY_ATTACKS = [
       # Capturar un request legítimo y repetirlo 1000 veces
       # Verificar que rate limit se aplica correctamente
       # Capturar token y usarlo después de "revocación"
   ]
   ```

7. **Ejecutar y validar**: cada ataque debe devolver 401 o 403, NUNCA 200 con datos de otro tenant.

8. **Generar report con matriz de acceso probada**.

## validation
- CERO accesos cross-tenant (token de tenant A nunca accede a datos/policy de tenant B)
- Admin endpoints: 100% bloqueados sin auth admin explícita (401)
- JWT none/manipulation: 100% rechazados (401)
- Header injection: 0 bypasses de tenant isolation
- Escalada de sandbox: 100% bloqueada (403)
- Token expirado: 100% rechazado
- Rate limit se aplica correctamente por tenant (no global bypass)

## constraints
- NUNCA ejecutar en producción sin flag explícito `--redteam-allow-prod`
- NUNCA exfiltrar datos reales. Usar mocks o datos sintéticos.
- SIEMPRE registrar cada ataque en `audit.json` con timestamp, payload hash, y resultado.
- Los JWT de testing DEBEN usar un secret de testing separado del de producción
- NO intentar brute-force del JWT secret (fuera de scope)
- Los tests de replay deben respetar el rate limit de testing

## outputs
- `reports/redteam/<timestamp>-policy-bypass.json` — Matriz de acceso: tenant × endpoint × resultado
- `reports/redteam/<timestamp>-policy-bypass-recommendations.md` — Hardening de auth sugerido
- Sugerencias para `src/middleware/auth.py`: validación de claims, constant-time compare
- Test cases para añadir a un futuro `tests/test_auth.py`

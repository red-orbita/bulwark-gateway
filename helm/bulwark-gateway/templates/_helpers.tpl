{{/*
Expand the name of the chart.
*/}}
{{- define "bulwark-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "bulwark-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "bulwark-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "bulwark-gateway.labels" -}}
helm.sh/chart: {{ include "bulwark-gateway.chart" . }}
app.kubernetes.io/part-of: bulwark-gateway
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Proxy labels
*/}}
{{- define "bulwark-gateway.proxy.labels" -}}
{{ include "bulwark-gateway.labels" . }}
app.kubernetes.io/name: proxy
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Proxy selector labels
*/}}
{{- define "bulwark-gateway.proxy.selectorLabels" -}}
app.kubernetes.io/name: proxy
{{- end }}

{{/*
Admin labels
*/}}
{{- define "bulwark-gateway.admin.labels" -}}
{{ include "bulwark-gateway.labels" . }}
app.kubernetes.io/name: admin
app.kubernetes.io/component: admin
{{- end }}

{{/*
Admin selector labels
*/}}
{{- define "bulwark-gateway.admin.selectorLabels" -}}
app.kubernetes.io/name: admin
{{- end }}

{{/*
Redis labels
*/}}
{{- define "bulwark-gateway.redis.labels" -}}
{{ include "bulwark-gateway.labels" . }}
app.kubernetes.io/name: redis
app.kubernetes.io/component: cache
{{- end }}

{{/*
Redis selector labels
*/}}
{{- define "bulwark-gateway.redis.selectorLabels" -}}
app.kubernetes.io/name: redis
{{- end }}

{{/*
GA Guard sidecar labels
*/}}
{{- define "bulwark-gateway.gaGuard.labels" -}}
{{ include "bulwark-gateway.labels" . }}
app.kubernetes.io/name: ga-guard
app.kubernetes.io/component: scanner-sidecar
{{- end }}

{{/*
GA Guard sidecar selector labels
*/}}
{{- define "bulwark-gateway.gaGuard.selectorLabels" -}}
app.kubernetes.io/name: ga-guard
{{- end }}

{{/*
GA Guard classify URL — explicit override wins; otherwise auto-derive the
in-cluster sidecar Service DNS when the bundled sidecar is enabled. Empty when
neither is set (the scanner then boots disabled/inert).
*/}}
{{- define "bulwark-gateway.gaGuard.url" -}}
{{- if .Values.proxy.gaGuard.url }}
{{- .Values.proxy.gaGuard.url }}
{{- else if .Values.proxy.gaGuard.sidecar.enabled }}
{{- printf "http://ga-guard.%s.svc.cluster.local:%d/classify" (include "bulwark-gateway.namespace" .) (int .Values.proxy.gaGuard.sidecar.port) }}
{{- end }}
{{- end }}

{{/*
Namespace
*/}}
{{- define "bulwark-gateway.namespace" -}}
{{- .Values.namespace.name | default "bulwark-gateway" }}
{{- end }}

{{/*
Proxy image — supports digest pinning (overrides tag when set)
*/}}
{{- define "bulwark-gateway.proxy.image" -}}
{{- if .Values.proxy.image.digest }}
{{- printf "%s@%s" .Values.proxy.image.repository .Values.proxy.image.digest }}
{{- else }}
{{- $tag := .Values.proxy.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.proxy.image.repository $tag }}
{{- end }}
{{- end }}

{{/*
Admin image — supports digest pinning (overrides tag when set)
*/}}
{{- define "bulwark-gateway.admin.image" -}}
{{- if .Values.admin.image.digest }}
{{- printf "%s@%s" .Values.admin.image.repository .Values.admin.image.digest }}
{{- else }}
{{- $tag := .Values.admin.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.admin.image.repository $tag }}
{{- end }}
{{- end }}

{{/*
Redis URL — internal (in-cluster) or external (cloud/on-premise)
Supports standalone, bulwark, and cluster modes.
*/}}
{{- define "bulwark-gateway.redis.url" -}}
{{- if .Values.redis.enabled }}
  {{- if eq .Values.redis.mode "bulwark" }}
    {{- $ns := include "bulwark-gateway.namespace" . -}}
    {{- $masterName := .Values.redis.bulwark.masterName -}}
    {{- $replicas := int .Values.redis.bulwark.replicas -}}
    {{- $nodes := list -}}
    {{- range $i := until $replicas -}}
      {{- $nodes = append $nodes (printf "redis-bulwark-%d.redis-bulwark.%s.svc.cluster.local:26379" $i $ns) -}}
    {{- end -}}
    {{- printf "redis+bulwark://%s/0?bulwark_master=%s" (join "," $nodes) $masterName }}
  {{- else if eq .Values.redis.mode "cluster" }}
    {{- $ns := include "bulwark-gateway.namespace" . -}}
    {{- $nodeCount := int .Values.redis.cluster.nodes -}}
    {{- $nodes := list -}}
    {{- range $i := until $nodeCount -}}
      {{- $nodes = append $nodes (printf "redis-cluster-%d.redis-cluster.%s.svc.cluster.local:6379" $i $ns) -}}
    {{- end -}}
    {{- printf "redis+cluster://%s/0" (join "," $nodes) }}
  {{- else }}
    {{- printf "redis://redis.%s.svc.cluster.local.:6379/0" (include "bulwark-gateway.namespace" .) }}
  {{- end }}
{{- else }}
  {{- if .Values.externalRedis.bulwark.enabled }}
    {{- $scheme := ternary "rediss+bulwark" "redis+bulwark" .Values.externalRedis.tls -}}
    {{- $masterName := .Values.externalRedis.bulwark.masterName -}}
    {{- printf "%s://%s/%d?bulwark_master=%s" $scheme (join "," .Values.externalRedis.bulwark.nodes) (int .Values.externalRedis.db) $masterName }}
  {{- else }}
    {{- $scheme := ternary "rediss" "redis" .Values.externalRedis.tls -}}
    {{- printf "%s://%s:%d/%d" $scheme .Values.externalRedis.host (int .Values.externalRedis.port) (int .Values.externalRedis.db) }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Redis Bulwark master name — used by application configuration
*/}}
{{- define "bulwark-gateway.redis.masterName" -}}
{{- if and .Values.redis.enabled (eq .Values.redis.mode "bulwark") }}
{{- .Values.redis.bulwark.masterName }}
{{- else if and (not .Values.redis.enabled) .Values.externalRedis.bulwark.enabled }}
{{- .Values.externalRedis.bulwark.masterName }}
{{- else }}
{{- printf "" }}
{{- end }}
{{- end }}

{{/*
Redis password secret name — auto-generated or existing
*/}}
{{- define "bulwark-gateway.redis.secretName" -}}
{{- if and (not .Values.redis.enabled) .Values.externalRedis.existingSecret }}
{{- .Values.externalRedis.existingSecret }}
{{- else }}
{{- printf "bulwark-redis-secrets" }}
{{- end }}
{{- end }}

{{/*
Redis password secret key
*/}}
{{- define "bulwark-gateway.redis.secretKey" -}}
{{- if and (not .Values.redis.enabled) .Values.externalRedis.existingSecret }}
{{- .Values.externalRedis.existingSecretKey | default "redis-password" }}
{{- else }}
{{- printf "redis-password" }}
{{- end }}
{{- end }}

{{/*
Validate required values
*/}}
{{- define "bulwark-gateway.redis.image" -}}
{{- if .Values.redis.image.digest -}}
{{- printf "%s@%s" .Values.redis.image.repository .Values.redis.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.redis.image.repository .Values.redis.image.tag -}}
{{- end -}}
{{- end -}}

{{- define "bulwark-gateway.validateValues" -}}
{{- if not (kindIs "slice" .Values.proxy.corsOrigins) }}
{{- fail "proxy.corsOrigins must be a list of explicit HTTP(S) origins" }}
{{- end }}
{{- range .Values.proxy.corsOrigins }}
{{- if or (not (kindIs "string" .)) (not (regexMatch "^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$" .)) }}
{{- fail "proxy.corsOrigins must contain explicit HTTP(S) origins without wildcards or paths" }}
{{- end }}
{{- end }}
{{- $adminPG := .Values.admin.database.postgresql -}}
{{- if and .Values.networkPolicies.enabled (eq .Values.admin.database.type "postgresql") (or (not $adminPG.internal) $adminPG.host) }}
{{- if or (empty $adminPG.host) (not (regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$" $adminPG.egressCIDR)) }}
{{- fail "external admin PostgreSQL requires host and egressCIDR with an exact IPv4 /32 when NetworkPolicy is enabled" }}
{{- end }}
{{- range $octet := splitList "." (trimSuffix "/32" $adminPG.egressCIDR) }}
{{- if or (not (regexMatch "^(0|[1-9][0-9]{0,2})$" $octet)) (gt (int $octet) 255) }}
{{- fail "external admin PostgreSQL egressCIDR must contain a valid IPv4 address" }}
{{- end }}
{{- end }}
{{- if and (regexMatch "^[0-9.]+$" $adminPG.host) (ne (printf "%s/32" $adminPG.host) $adminPG.egressCIDR) }}
{{- fail "external admin PostgreSQL IP host must match egressCIDR" }}
{{- end }}
{{- end }}
{{- if and .Values.redis.existingClaim (or (ne .Values.redis.mode "standalone") (not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" .Values.redis.existingClaim)) (gt (len .Values.redis.existingClaim) 253)) }}
{{- fail "redis.existingClaim requires standalone mode and a valid PVC name" }}
{{- end }}
{{- if and .Values.redis.image.digest (not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.redis.image.digest)) }}
{{- fail "redis.image.digest must be sha256 followed by 64 lowercase hexadecimal characters" }}
{{- end }}
{{- if or (not (regexMatch "^[1-9][0-9]{0,2}$" (toJson .Values.redis.startupFailureThreshold))) (gt (int .Values.redis.startupFailureThreshold) 120) }}
{{- fail "redis.startupFailureThreshold must be an integer in 1..120" }}
{{- end }}
{{- $attachments := .Values.proxy.attachments -}}
{{- if not (kindIs "map" $attachments) }}
{{- fail "proxy.attachments must be a YAML map" }}
{{- end }}
{{- range $key := list "enabled" "extractDocuments" "parserIsolationConfirmed" }}
{{- if not (kindIs "bool" (index $attachments $key)) }}
{{- fail (printf "proxy.attachments.%s must be a YAML boolean" $key) }}
{{- end }}
{{- end }}
{{- range $key, $max := dict "maxFileBytes" 65536 "maxTotalBytes" 65536 "maxCount" 5 "maxDocumentBytes" 2097152 }}
{{- $value := index $attachments $key -}}
{{- /* Keep JSON quotes: numeric strings must not pass as numbers. Bound before conversion. */ -}}
{{- if not (regexMatch "^[1-9][0-9]{0,6}$" (toJson $value)) }}
{{- fail (printf "proxy.attachments.%s must be an integer in 1..%d (not a string or boolean)" $key $max) }}
{{- end }}
{{- if gt (int64 $value) (int64 $max) }}
{{- fail (printf "proxy.attachments.%s must be an integer in 1..%d (not a string or boolean)" $key $max) }}
{{- end }}
{{- end }}
{{- if and $attachments.extractDocuments (not $attachments.parserIsolationConfirmed) }}
{{- fail "proxy.attachments.extractDocuments requires parserIsolationConfirmed=true after operator validation of native tools and Bubblewrap isolation" }}
{{- end }}
{{- if ne (toString $attachments.extractionWorkDir) "/tmp" }}
{{- fail "proxy.attachments.extractionWorkDir must be /tmp, the existing ephemeral mount; no directory bootstrap is provided" }}
{{- end }}
{{- if or (not (kindIs "string" $attachments.extractionLanguages)) (not (regexMatch "^[a-z][a-z0-9_]{1,31}(\\+[a-z][a-z0-9_]{1,31}){0,2}$" (toString $attachments.extractionLanguages))) }}
{{- fail "proxy.attachments.extractionLanguages must match the runtime language syntax: one to three lowercase names, 2..32 characters each, joined by '+'" }}
{{- end }}
{{- $tmp := toString $attachments.extractionTmpSize }}
{{- if not (regexMatch "^[1-9][0-9]{2,3}Mi$" $tmp) }}
{{- fail "proxy.attachments.extractionTmpSize must be whole Mi in 256..4096Mi" }}
{{- end }}
{{- $tmpMi := int (trimSuffix "Mi" $tmp) }}
{{- if or (lt $tmpMi 256) (gt $tmpMi 4096) }}
{{- fail "proxy.attachments.extractionTmpSize must be whole Mi in 256..4096Mi" }}
{{- end }}
{{- if or $attachments.extractDocuments $attachments.parserIsolationConfirmed }}
{{- if not (regexMatch "^[1-9][0-9]?$" (toJson .Values.proxy.workers)) }}
{{- fail "Document extraction requires integer proxy.workers in 1..16 and at least 256Mi per worker" }}
{{- end }}
{{- if or (gt (int .Values.proxy.workers) 16) (lt $tmpMi (mul 256 (int .Values.proxy.workers))) }}
{{- fail "Document extraction requires integer proxy.workers in 1..16 and at least 256Mi per worker" }}
{{- end }}
{{- if .Values.dedicatedTenants.enabled }}
{{- fail "Document extraction is not provisioned for dedicatedTenants: separate proxy scratch volumes remain 50Mi" }}
{{- end }}
{{- end }}
{{- $outbox := .Values.telemetry.outbox -}}
{{- $service := $attachments.service -}}
{{- if not (kindIs "map" $service) }}
{{- fail "proxy.attachments.service must be a YAML map" }}
{{- end }}
{{- range $key := list "enabled" "storageProtectionConfirmed" }}
{{- if not (kindIs "bool" (index $service $key)) }}
{{- fail (printf "proxy.attachments.service.%s must be a YAML boolean" $key) }}
{{- end }}
{{- end }}
{{- if $service.enabled }}
{{- if or (ne (toJson .Values.proxy.workers) "1") (ne (toJson .Values.proxy.replicas) "1") (ne (toJson .Values.proxy.autoscaling.enabled) "false") .Values.dedicatedTenants.enabled }}
{{- fail "attachment service requires one worker/replica, autoscaling=false and dedicatedTenants=false" }}
{{- end }}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.proxy.image.digest) }}
{{- fail "attachment service requires an immutable proxy.image.digest" }}
{{- end }}
{{- if not $service.storageProtectionConfirmed }}
{{- fail "attachment service requires storageProtectionConfirmed=true after validating encryption, backup access and retention" }}
{{- end }}
{{- if ne .Values.persistence.accessMode "ReadWriteMany" }}
{{- fail "attachment service requires persistence.accessMode=ReadWriteMany for existing proxy/admin shared volumes" }}
{{- end }}
{{- range $key, $bounds := dict "maxDocuments" (list 1 10000) "maxBytes" (list 1048576 1073741824) "maxPerTenant" (list 1 1000) "ttlSeconds" (list 60 86400) }}
{{- $value := index $service $key }}
{{- if or (not (regexMatch "^[1-9][0-9]{0,9}$" (toJson $value))) (lt (int64 $value) (int64 (first $bounds))) (gt (int64 $value) (int64 (last $bounds))) }}
{{- fail (printf "attachment service %s must be an integer in %d..%d" $key (first $bounds) (last $bounds)) }}
{{- end }}
{{- end }}
{{- if eq $service.storage "local-sqlite" }}
{{- if not (has $service.local.accessMode (list "ReadWriteOnce" "ReadWriteOncePod")) }}
{{- fail "attachment service local PVC must use ReadWriteOnce or ReadWriteOncePod" }}
{{- end }}
{{- if or (has $service.local.existingClaim (list "admin-data" "policies" "siem-stats" "telemetry-data" "proxy-outbox" "notifications-data" "enrichment-data" "ml-models" "reports")) (and $service.local.existingClaim (eq $service.local.existingClaim $outbox.local.existingClaim)) }}
{{- fail "attachment service requires a dedicated PVC, not an existing shared application/outbox volume" }}
{{- end }}
{{- if and $service.local.existingClaim (not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" $service.local.existingClaim)) }}
{{- fail "attachment service existingClaim must be a Kubernetes PVC name" }}
{{- end }}
{{- if not (regexMatch "^[1-9][0-9]{0,3}Gi$" (toString $service.local.size)) }}
{{- fail "attachment service local.size must be whole Gi (at least 1Gi), allowing journal/metadata headroom" }}
{{- end }}
{{- if lt (mul (int64 (trimSuffix "Gi" $service.local.size)) 1073741824) (mul (int64 $service.maxBytes) 4) }}
{{- fail "attachment service local.size must reserve at least four times maxBytes for database/journal overhead" }}
{{- end }}
{{- else if eq $service.storage "shared-postgresql" }}
{{- if or (ne $outbox.mode "shared-postgresql") (ne $outbox.postgresql.sslMode "verify-full") }}
{{- fail "attachment shared-postgresql requires telemetry.outbox shared-postgresql with sslMode=verify-full" }}
{{- end }}
{{- else }}
{{- fail "attachment service storage must be local-sqlite or shared-postgresql" }}
{{- end }}
{{- end }}
{{- if not (has $outbox.mode (list "legacy" "local-durable" "shared-postgresql")) }}
{{- fail "telemetry.outbox.mode must be legacy, local-durable or shared-postgresql" }}
{{- end }}
{{- $admission := .Values.telemetry.auditAdmission -}}
{{- if not (kindIs "bool" $admission.required) }}
{{- fail "telemetry.auditAdmission.required must be a YAML boolean" }}
{{- end }}
{{- if or (not (regexMatch "^[1-9][0-9]{0,4}$" ($admission.timeoutMs | toJson | trimAll "\""))) (gt (int64 $admission.timeoutMs) 10000) }}
{{- fail "telemetry.auditAdmission.timeoutMs must be an integer in 1..10000" }}
{{- end }}
{{- if and $admission.required (or (not .Values.telemetry.enabled) (eq $outbox.mode "legacy")) }}
{{- fail "telemetry.auditAdmission.required requires telemetry.enabled=true and local-durable or shared-postgresql outbox mode" }}
{{- end }}
{{- if ne $outbox.mode "legacy" }}
{{- range $value := list .Values.telemetry.enabled .Values.proxy.autoscaling.enabled .Values.dedicatedTenants.enabled }}
{{- if not (kindIs "bool" $value) }}
{{- fail "durable outbox enable switches must be YAML booleans, not strings" }}
{{- end }}
{{- end }}
{{- if not .Values.telemetry.enabled }}
{{- fail "durable outbox requires telemetry.enabled=true" }}
{{- end }}
{{- if .Values.dedicatedTenants.enabled }}
{{- fail "durable outbox is not wired for dedicatedTenants; disable dedicatedTenants" }}
{{- end }}
{{- if ne .Values.persistence.accessMode "ReadWriteMany" }}
{{- fail "durable outbox requires persistence.accessMode=ReadWriteMany for the remaining proxy/admin shared PVCs; the local outbox has its own RWO PVC" }}
{{- end }}
{{- end }}
{{- if eq $outbox.mode "local-durable" }}
{{- if or (ne (toString .Values.proxy.workers) "1") (ne (toString .Values.proxy.replicas) "1") .Values.proxy.autoscaling.enabled }}
{{- fail "local-durable requires proxy.workers=1, proxy.replicas=1 and proxy.autoscaling.enabled=false" }}
{{- end }}
{{- if not (has $outbox.local.accessMode (list "ReadWriteOnce" "ReadWriteOncePod")) }}
{{- fail "local-durable accessMode must be ReadWriteOnce or ReadWriteOncePod, never a shared filesystem" }}
{{- end }}
{{- if has $outbox.local.existingClaim (list "telemetry-data" "admin-data" "policies" "siem-stats" "enrichment-data" "notifications-data" "reports" "ml-models") }}
{{- fail "local-durable existingClaim must be a dedicated proxy-only PVC" }}
{{- end }}
{{- if not (regexMatch "^[1-9][0-9]*(Ki|Mi|Gi|Ti)?$" (toString $outbox.local.size)) }}
{{- fail "local-durable requires a nonempty local.size: positive integer bytes or Ki/Mi/Gi/Ti" }}
{{- end }}
{{- end }}
{{- if eq $outbox.mode "shared-postgresql" }}
{{- $pg := $outbox.postgresql -}}
{{- if or (empty $pg.existingSecret) (empty $pg.urlKey) (empty $pg.host) }}
{{- fail "shared-postgresql requires postgresql.existingSecret, urlKey and host" }}
{{- end }}
{{- if or (not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" $pg.host)) (gt (len $pg.host) 253) }}
{{- fail "shared-postgresql host must be a lowercase DNS name or IPv4 address, without URL credentials or port" }}
{{- end }}
{{- if or (not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" $pg.existingSecret)) (gt (len $pg.existingSecret) 253) }}
{{- fail "shared-postgresql existingSecret must be a Kubernetes Secret name" }}
{{- end }}
{{- range $key := list $pg.urlKey $pg.caKey }}
{{- if and $key (or (not (regexMatch "^[A-Za-z0-9._-]+$" $key)) (gt (len $key) 253)) }}
{{- fail "shared-postgresql urlKey and caKey must be Kubernetes Secret keys" }}
{{- end }}
{{- end }}
{{- if or (not (kindIs "bool" $pg.ssl)) (not $pg.ssl) (not (has $pg.sslMode (list "require" "verify-ca" "verify-full"))) }}
{{- fail "shared-postgresql requires ssl=true and sslMode=require, verify-ca or verify-full" }}
{{- end }}
{{- range $key, $value := dict "port" $pg.port "poolMin" $pg.poolMin "poolMax" $pg.poolMax "maxEvents" $pg.maxEvents "maxBytes" $pg.maxBytes }}
{{- if not (regexMatch "^[1-9][0-9]*$" ($value | toJson | trimAll "\"")) }}
{{- fail (printf "shared-postgresql %s must be a positive integer" $key) }}
{{- end }}
{{- end }}
{{- if or (gt (int64 $pg.port) 65535) (gt (int64 $pg.poolMin) (int64 $pg.poolMax)) (gt (int64 $pg.maxEvents) 10000000) (gt (int64 $pg.maxBytes) 1099511627776) }}
{{- fail "shared-postgresql port, pool bounds or capacity is out of range" }}
{{- end }}
{{- if not .Values.networkPolicies.enabled }}
{{- fail "shared-postgresql requires networkPolicies.enabled=true" }}
{{- end }}
{{- range $key, $value := dict "workers" .Values.proxy.workers "replicas" .Values.proxy.replicas }}
{{- if not (regexMatch "^[1-9][0-9]*$" (toString $value)) }}
{{- fail (printf "shared-postgresql proxy.%s must be a positive integer" $key) }}
{{- end }}
{{- end }}
{{- if .Values.proxy.autoscaling.enabled }}
{{- range $value := list .Values.proxy.autoscaling.minReplicas .Values.proxy.autoscaling.maxReplicas }}
{{- if not (regexMatch "^[1-9][0-9]*$" ($value | toJson | trimAll "\"")) }}
{{- fail "shared-postgresql requires integer HPA replica bounds" }}
{{- end }}
{{- end }}
{{- if or (lt (int .Values.proxy.autoscaling.minReplicas) 1) (lt (int .Values.proxy.autoscaling.maxReplicas) (int .Values.proxy.autoscaling.minReplicas)) }}
{{- fail "shared-postgresql requires valid HPA replica bounds" }}
{{- end }}
{{- end }}
{{- $eg := $pg.egress -}}
{{- if $eg.cidr }}
{{- if or $eg.namespace $eg.podLabels }}
{{- fail "PostgreSQL egress must use either cidr or namespace+podLabels, not both" }}
{{- end }}
{{- if not (regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}/(8|9|[12][0-9]|3[0-2])$" $eg.cidr) }}
{{- fail "PostgreSQL egress.cidr must be a scoped IPv4 CIDR (/8..32), never allow-all" }}
{{- end }}
{{- range $octet := splitList "." (first (splitList "/" $eg.cidr)) }}
{{- if or (gt (int $octet) 255) (not (regexMatch "^(0|[1-9][0-9]{0,2})$" $octet)) }}
{{- fail "PostgreSQL egress.cidr has an invalid IPv4 address" }}
{{- end }}
{{- end }}
{{- $address := int64 0 -}}
{{- range $octet := splitList "." (first (splitList "/" $eg.cidr)) }}
{{- $address = add (mul $address 256) (int64 $octet) -}}
{{- end }}
{{- $blockSize := int64 1 -}}
{{- range until (int (sub 32 (int (last (splitList "/" $eg.cidr))))) }}
{{- $blockSize = mul $blockSize 2 -}}
{{- end }}
{{- if ne (mod $address $blockSize) (int64 0) }}
{{- fail "PostgreSQL egress.cidr must be a canonical network (no host bits)" }}
{{- end }}
{{- else if or (empty $eg.namespace) (empty $eg.podLabels) (not (kindIs "map" $eg.podLabels)) }}
{{- fail "PostgreSQL egress requires scoped cidr or namespace and nonempty podLabels" }}
{{- end }}
{{- if $eg.namespace }}
{{- if or (gt (len $eg.namespace) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $eg.namespace)) }}
{{- fail "PostgreSQL egress.namespace must be an explicit Kubernetes namespace" }}
{{- end }}
{{- range $key, $value := $eg.podLabels }}
{{- if or (not (regexMatch "^([a-z0-9]([a-z0-9.-]*[a-z0-9])?/)?[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" $key)) (not (kindIs "string" $value)) (empty $value) (gt (len (toString $value)) 63) (not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$" (toString $value))) }}
{{- fail "PostgreSQL egress.podLabels must contain explicit nonempty label values, not wildcards" }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- if .Values.proxy.enrichment.enabled }}
{{- $enrich := .Values.proxy.enrichment -}}
{{- if not (kindIs "bool" $enrich.enabled) }}
{{- fail "proxy.enrichment.enabled must be a YAML boolean" }}
{{- end }}
{{- if or (hasKey $enrich "initImage") (hasKey $enrich "download") }}
{{- fail "enrichment initImage/download is no longer supported; use existingModelClaim and modelManifest" }}
{{- end }}
{{- if or (empty $enrich.existingModelClaim) (empty $enrich.modelManifest) }}
{{- fail "enrichment requires existingModelClaim and a trusted SHA-256 modelManifest; no models are downloaded. Set proxy.enrichment.enabled=false to opt out" }}
{{- end }}
{{- if or (not (kindIs "map" $enrich.modelManifest)) (gt (len $enrich.modelManifest) 256) }}
{{- fail "enrichment modelManifest must be a map of at most 256 files" }}
{{- end }}
{{- range $name := list "config.json" "tokenizer.json" "modules.json" "model.safetensors" "1_Pooling/config.json" }}
{{- if not (hasKey $enrich.modelManifest $name) }}
{{- fail (printf "enrichment modelManifest is missing required file %s" $name) }}
{{- end }}
{{- end }}
{{- range $path, $sha := $enrich.modelManifest }}
{{- if or (not (regexMatch "^[A-Za-z0-9_-][A-Za-z0-9_./-]*$" $path)) (regexMatch "(^|/)\\.\\.?(/|$)" $path) (hasSuffix "/" $path) (contains "//" $path) (not (regexMatch "^[a-fA-F0-9]{64}$" (toString $sha))) }}
{{- fail "enrichment modelManifest requires safe relative paths and 64-character SHA-256 digests" }}
{{- end }}
{{- end }}
{{- if or (not (regexMatch "^[1-9][0-9]*$" ($enrich.modelMaxBytes | toJson | trimAll "\""))) (gt (int64 $enrich.modelMaxBytes) 1073741824) }}
{{- fail "enrichment modelMaxBytes must be 1..1073741824" }}
{{- end }}
{{- end }}
{{- if and (eq .Values.admin.database.type "postgresql") (not (has .Values.admin.database.postgresql.sslMode (list "disable" "require" "verify-ca" "verify-full"))) }}
{{- fail "admin.database.postgresql.sslMode must be disable, require, verify-ca or verify-full" }}
{{- end }}
{{- if and (eq .Values.admin.database.type "postgresql") .Values.admin.database.postgresql.internal (empty .Values.admin.database.postgresql.host) (ne .Values.admin.database.postgresql.sslMode "disable") }}
{{- fail "Bundled PostgreSQL has no TLS provisioning: use an external TLS database or explicitly choose sslMode=disable for an isolated development deployment" }}
{{- end }}
{{- if and (eq .Values.backend.type "ip") (empty .Values.backend.ip) }}
{{- fail "backend.ip is REQUIRED when backend.type is 'ip'. Set it to your LLM backend IP address." }}
{{- end }}
{{- if and .Values.networkPolicies.enabled (eq .Values.backend.type "ip") }}
{{- if not (regexMatch "^([0-9]{1,3}\\.){3}[0-9]{1,3}$" .Values.backend.ip) }}
{{- fail "backend.ip must be an explicit IPv4 address for the scoped NetworkPolicy" }}
{{- end }}
{{- range $octet := splitList "." .Values.backend.ip }}
{{- if or (not (regexMatch "^(0|[1-9][0-9]{0,2})$" $octet)) (gt (int $octet) 255) }}
{{- fail "backend.ip must contain valid IPv4 octets" }}
{{- end }}
{{- end }}
{{- if or (not (regexMatch "^[1-9][0-9]{0,4}$" (toJson .Values.backend.port))) (gt (int .Values.backend.port) 65535) }}
{{- fail "backend.port must be an integer in 1..65535" }}
{{- end }}
{{- end }}
{{- if and (eq .Values.backend.type "externalName") (empty .Values.backend.externalName) }}
{{- fail "backend.externalName is REQUIRED when backend.type is 'externalName'. Set it to your LLM backend DNS name." }}
{{- end }}
{{- if and (not .Values.redis.enabled) (not .Values.externalRedis.bulwark.enabled) (empty .Values.externalRedis.host) }}
{{- fail "externalRedis.host is REQUIRED when redis.enabled=false (unless using externalRedis.bulwark). Set it to your Redis endpoint." }}
{{- end }}
{{- if and .Values.redis.enabled (eq .Values.redis.mode "bulwark") (not .Values.redis.bulwark.enabled) }}
{{- fail "redis.bulwark.enabled must be true when redis.mode is 'bulwark'." }}
{{- end }}
{{- if and .Values.redis.enabled (eq .Values.redis.mode "cluster") (not .Values.redis.cluster.enabled) }}
{{- fail "redis.cluster.enabled must be true when redis.mode is 'cluster'." }}
{{- end }}
{{- if and .Values.redis.enabled (eq .Values.redis.mode "cluster") (lt (int .Values.redis.cluster.nodes) 6) }}
{{- fail "redis.cluster.nodes must be at least 6 (3 masters + 3 replicas) for Redis Cluster mode." }}
{{- end }}
{{- if and (not .Values.redis.enabled) .Values.externalRedis.bulwark.enabled (empty .Values.externalRedis.bulwark.nodes) }}
{{- fail "externalRedis.bulwark.nodes is REQUIRED when externalRedis.bulwark.enabled=true. Provide at least one bulwark host:port pair." }}
{{- end }}
{{- end }}

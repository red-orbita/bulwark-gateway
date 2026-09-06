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
{{- define "bulwark-gateway.validateValues" -}}
{{- if and (eq .Values.backend.type "ip") (empty .Values.backend.ip) }}
{{- fail "backend.ip is REQUIRED when backend.type is 'ip'. Set it to your LLM backend IP address." }}
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

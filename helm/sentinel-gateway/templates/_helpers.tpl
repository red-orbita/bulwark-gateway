{{/*
Expand the name of the chart.
*/}}
{{- define "sentinel-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "sentinel-gateway.fullname" -}}
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
{{- define "sentinel-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sentinel-gateway.labels" -}}
helm.sh/chart: {{ include "sentinel-gateway.chart" . }}
app.kubernetes.io/part-of: sentinel-gateway
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}

{{/*
Proxy labels
*/}}
{{- define "sentinel-gateway.proxy.labels" -}}
{{ include "sentinel-gateway.labels" . }}
app.kubernetes.io/name: proxy
app.kubernetes.io/component: gateway
{{- end }}

{{/*
Proxy selector labels
*/}}
{{- define "sentinel-gateway.proxy.selectorLabels" -}}
app.kubernetes.io/name: proxy
{{- end }}

{{/*
Admin labels
*/}}
{{- define "sentinel-gateway.admin.labels" -}}
{{ include "sentinel-gateway.labels" . }}
app.kubernetes.io/name: admin
app.kubernetes.io/component: admin
{{- end }}

{{/*
Admin selector labels
*/}}
{{- define "sentinel-gateway.admin.selectorLabels" -}}
app.kubernetes.io/name: admin
{{- end }}

{{/*
Redis labels
*/}}
{{- define "sentinel-gateway.redis.labels" -}}
{{ include "sentinel-gateway.labels" . }}
app.kubernetes.io/name: redis
app.kubernetes.io/component: cache
{{- end }}

{{/*
Redis selector labels
*/}}
{{- define "sentinel-gateway.redis.selectorLabels" -}}
app.kubernetes.io/name: redis
{{- end }}

{{/*
Namespace
*/}}
{{- define "sentinel-gateway.namespace" -}}
{{- .Values.namespace.name | default "sentinel-gateway" }}
{{- end }}

{{/*
Proxy image
*/}}
{{- define "sentinel-gateway.proxy.image" -}}
{{- $tag := .Values.proxy.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.proxy.image.repository $tag }}
{{- end }}

{{/*
Admin image
*/}}
{{- define "sentinel-gateway.admin.image" -}}
{{- $tag := .Values.admin.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.admin.image.repository $tag }}
{{- end }}

{{/*
Redis URL — internal (in-cluster) or external (cloud/on-premise)
*/}}
{{- define "sentinel-gateway.redis.url" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://redis.%s.svc.cluster.local:6379/0" (include "sentinel-gateway.namespace" .) }}
{{- else }}
{{- $scheme := ternary "rediss" "redis" .Values.externalRedis.tls }}
{{- printf "%s://%s:%d/%d" $scheme .Values.externalRedis.host (int .Values.externalRedis.port) (int .Values.externalRedis.db) }}
{{- end }}
{{- end }}

{{/*
Redis password secret name — auto-generated or existing
*/}}
{{- define "sentinel-gateway.redis.secretName" -}}
{{- if and (not .Values.redis.enabled) .Values.externalRedis.existingSecret }}
{{- .Values.externalRedis.existingSecret }}
{{- else }}
{{- printf "sentinel-redis-secrets" }}
{{- end }}
{{- end }}

{{/*
Redis password secret key
*/}}
{{- define "sentinel-gateway.redis.secretKey" -}}
{{- if and (not .Values.redis.enabled) .Values.externalRedis.existingSecret }}
{{- .Values.externalRedis.existingSecretKey | default "redis-password" }}
{{- else }}
{{- printf "redis-password" }}
{{- end }}
{{- end }}

{{/*
Validate required values
*/}}
{{- define "sentinel-gateway.validateValues" -}}
{{- if and (eq .Values.backend.type "ip") (empty .Values.backend.ip) }}
{{- fail "backend.ip is REQUIRED when backend.type is 'ip'. Set it to your LLM backend IP address." }}
{{- end }}
{{- if and (eq .Values.backend.type "externalName") (empty .Values.backend.externalName) }}
{{- fail "backend.externalName is REQUIRED when backend.type is 'externalName'. Set it to your LLM backend DNS name." }}
{{- end }}
{{- if and (not .Values.redis.enabled) (empty .Values.externalRedis.host) }}
{{- fail "externalRedis.host is REQUIRED when redis.enabled=false. Set it to your Redis endpoint (e.g., my-redis.cache.windows.net)." }}
{{- end }}
{{- end }}

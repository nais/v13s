{{/*
Expand the name of the chart.
*/}}
{{- define "v13s.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dependencytrack.name" -}}
{{- default "dependencytrack" }}
{{- end }}

{{/*
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "v13s.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "v13s.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "v13s.labels" -}}
helm.sh/chart: {{ include "v13s.chart" . }}
{{ include "v13s.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "dependencytrack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dependencytrack.name" . }}
app.kubernetes.io/instance: {{ include "dependencytrack.name" . }}-backend
{{- end }}

{{/*
Selector labels
*/}}
{{- define "v13s.selectorLabels" -}}
app.kubernetes.io/name: {{ include "v13s.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

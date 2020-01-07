{{/*
Expand the name of the chart.
*/}}
{{- define "harbor-scanner-aqua.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "harbor-scanner-aqua.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "harbor-scanner-aqua.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "harbor-scanner-aqua.labels" -}}
app.kubernetes.io/name: {{ include "harbor-scanner-aqua.name" . }}
helm.sh/chart: {{ include "harbor-scanner-aqua.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Return the proper imageRef as used by the init conainer template spec.
*/}}
{{- define "harbor-scanner-aqua.scannerImageRef" -}}
{{- $registryName := .Values.aqua.registry.server -}}
{{- $repositoryName := "scanner" -}}
{{- $tag := .Values.aqua.version | toString -}}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}

{{/*
Return the proper imageRef as used by the container template spec.
*/}}
{{- define "harbor-scanner-aqua.adapterImageRef" -}}
{{- $registryName := .Values.scanner.image.registry -}}
{{- $repositoryName := .Values.scanner.image.repository -}}
{{- $tag := .Values.scanner.image.tag | toString -}}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}

{{- define "imagePullSecret" }}
{{- printf "{\"auths\": {\"%s\": {\"auth\": \"%s\"}}}" .Values.aqua.registry.server (printf "%s:%s" .Values.aqua.registry.username .Values.aqua.registry.password | b64enc) | b64enc }}
{{- end }}

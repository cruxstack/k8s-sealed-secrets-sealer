{{- define "controlPlane.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "controlPlane.serviceAccountName" -}}
{{- default (include "controlPlane.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "controlPlane.selectorLabels" -}}
app.kubernetes.io/name: k8s-sealed-secrets-sealer-control-plane
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "controlPlane.labels" -}}
{{ include "controlPlane.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

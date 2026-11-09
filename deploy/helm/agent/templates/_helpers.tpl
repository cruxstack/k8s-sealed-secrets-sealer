{{- define "agent.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "agent.serviceAccountName" -}}
{{- default (include "agent.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "agent.controllerDeployment" -}}
{{- default .Values.controller.name .Values.controller.deploymentName -}}
{{- end -}}

{{- define "agent.selectorLabels" -}}
app.kubernetes.io/name: k8s-sealed-secrets-sealer-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agent.labels" -}}
{{ include "agent.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

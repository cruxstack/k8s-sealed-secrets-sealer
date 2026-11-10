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

{{/* the enabled capabilities, or "none": the agent then only reports its
controller's active key */}}
{{- define "agent.capabilities" -}}
{{- $caps := list -}}
{{- range $name, $on := .Values.capabilities -}}
{{- if $on }}{{ $caps = append $caps $name }}{{ end -}}
{{- end -}}
{{- if $caps }}{{ join "," $caps }}{{ else }}none{{ end -}}
{{- end -}}

{{/* the control plane's URL without a trailing slash: the control plane
compares the token audience with its own URL, which has none */}}
{{- define "agent.controlPlaneURL" -}}
{{- required "controlPlane.url is required" .Values.controlPlane.url | trimSuffix "/" -}}
{{- end -}}

{{- define "agent.audience" -}}
{{- default (include "agent.controlPlaneURL" .) .Values.identity.audience -}}
{{- end -}}

{{- define "agent.identityMode" -}}
{{- $mode := .Values.identity.mode -}}
{{- if not (has $mode (list "k8s-oidc" "aws-sts")) -}}
{{- fail (printf "identity.mode must be k8s-oidc or aws-sts, not %q" $mode) -}}
{{- end -}}
{{- $mode -}}
{{- end -}}

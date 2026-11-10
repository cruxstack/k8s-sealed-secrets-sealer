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

{{/*
APP_ENVS: the envs this control plane serves, each with its own table,
transit key and registry. An env without a registry of its own reads
registry-<name>.yaml from the registry ConfigMap.
*/}}
{{- define "sealer.envs" -}}
{{- $envs := list -}}
{{- range .Values.envs -}}
{{- $env := deepCopy . -}}
{{- $name := required "each of envs needs a name" $env.name -}}
{{- if not (or $env.registry $env.registryFile) -}}
{{- $_ := set $env "registryFile" (printf "/etc/k8s-sealed-secrets-sealer/registry-%s.yaml" $name) -}}
{{- end -}}
{{- $envs = append $envs $env -}}
{{- end -}}
{{- dict "envs" $envs | toYaml -}}
{{- end -}}

{{/*
Return the proper imageRef
*/}}
{{- define "harbor-scanner-aqua.imageRef" -}}
{{- $registryName := .Values.deployment.image.registry -}}
{{- $repositoryName := .Values.deployment.image.repository -}}
{{- $tag := .Values.deployment.image.tag | toString -}}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}

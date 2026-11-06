{{/* IPv4 only. Integer arithmetic stays within unsigned IPv4 space on Helm's int64. */}}
{{- define "services.ipv4Network" -}}
{{- if not (regexMatch `^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})/(0|[1-9]|[12][0-9]|3[0-2])$` .) -}}
  {{- fail "egress requires canonical IPv4 CIDRs; IPv6 is unsupported" -}}
{{- end -}}
{{- $parts := splitList "/" . -}}
{{- $address := int64 0 -}}
{{- range splitList "." (index $parts 0) -}}
  {{- $octet := int64 . -}}
  {{- if gt $octet (int64 255) -}}{{- fail "egress IPv4 octet exceeds 255" -}}{{- end -}}
  {{- $address = add (mul $address 256) $octet -}}
{{- end -}}
{{- $prefix := int (index $parts 1) -}}
{{- $size := int64 1 -}}
{{- range until (sub 32 $prefix | int) -}}{{- $size = mul $size 2 -}}{{- end -}}
{{- if ne (mod $address $size) (int64 0) -}}{{- fail "egress CIDR has host bits set" -}}{{- end -}}
{{- dict "address" $address "size" $size "prefix" $prefix | toJson -}}
{{- end -}}

{{- define "services.validateEgress" -}}
{{- range .egress -}}
  {{- if hasKey . "ipBlock" -}}
    {{- $network := include "services.ipv4Network" .ipBlock.cidr | fromJson -}}
    {{- range .ipBlock.except -}}
      {{- $excluded := include "services.ipv4Network" . | fromJson -}}
      {{- if or (le $excluded.prefix $network.prefix) (lt $excluded.address $network.address) (gt (add $excluded.address $excluded.size) (add $network.address $network.size)) -}}
        {{- fail "egress ipBlock except must be a strict subnet of cidr" -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- end -}}

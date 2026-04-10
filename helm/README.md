# device-service

![Version: 0.1.1](https://img.shields.io/badge/Version-0.1.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.2.0](https://img.shields.io/badge/AppVersion-0.2.0-informational?style=flat-square)

Device Service with CloudNativePG database cluster

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| IA-Generative |  |  |

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://cloudnative-pg.io/charts | cnpg(cluster) | 0.6.0 |
| oci://registry-1.docker.io/cloudpirates | valkey | 0.18.0 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| adminer.defaultServer | string | `""` |  |
| adminer.enabled | bool | `true` |  |
| adminer.image.pullPolicy | string | `"IfNotPresent"` |  |
| adminer.image.repository | string | `"adminer"` |  |
| adminer.image.tag | string | `"4"` |  |
| adminer.ingress.annotations | object | `{}` |  |
| adminer.ingress.className | string | `""` |  |
| adminer.ingress.enabled | bool | `false` |  |
| adminer.ingress.hosts[0].host | string | `"adminer.local"` |  |
| adminer.ingress.hosts[0].paths[0].path | string | `"/"` |  |
| adminer.ingress.hosts[0].paths[0].pathType | string | `"Prefix"` |  |
| adminer.ingress.tls | list | `[]` |  |
| adminer.resources | object | `{}` |  |
| adminer.service.port | int | `8080` |  |
| adminer.service.type | string | `"ClusterIP"` |  |
| affinity | object | `{}` |  |
| app.attestation.mode | string | `"prefer_hardware"` |  |
| app.attestation.reattestIntervalHours | int | `24` |  |
| app.attestation.requireDeviceSignature | bool | `false` |  |
| app.cors.allowCredentials | bool | `true` |  |
| app.cors.allowedHeaders | string | `"Accept,Authorization,Content-Type,Origin,X-Device-ID,X-Device-Nonce,X-Device-Timestamp,X-Device-Signature"` |  |
| app.cors.allowedMethods | string | `"GET,POST,PUT,PATCH,DELETE,OPTIONS"` |  |
| app.cors.allowedOrigins | string | `"*"` |  |
| app.cors.exposedHeaders | string | `""` |  |
| app.cors.maxAgeSeconds | int | `300` |  |
| app.enrollment.acrValues | string | `""` |  |
| app.enrollment.approvalMethods | string | `"email,cross_device"` |  |
| app.enrollment.autoApproveFirstDevice | bool | `true` |  |
| app.enrollment.crossDeviceMinTrust | int | `50` |  |
| app.enrollment.emailChallengeTTL | int | `30` |  |
| app.env | string | `"production"` |  |
| app.keycloak.clientId | string | `"device-cli"` |  |
| app.keycloak.jwksEndpoint | string | `"http://keycloak:8080/realms/myapp/protocol/openid-connect/certs"` |  |
| app.keycloak.publicUri | string | `"http://localhost:8081/"` |  |
| app.keycloak.realm | string | `"myapp"` |  |
| app.keycloak.redirectUri | string | `"http://localhost:8082/"` |  |
| app.port | string | `"8080"` |  |
| app.risk.thresholdFull | int | `70` |  |
| app.risk.thresholdLimited | int | `40` |  |
| app.smtp.authType | string | `"none"` |  |
| app.smtp.encryption | string | `"none"` |  |
| app.smtp.from | string | `"device-service@localhost"` |  |
| app.smtp.host | string | `"localhost"` |  |
| app.smtp.password | string | `""` |  |
| app.smtp.port | string | `"1025"` |  |
| app.smtp.username | string | `""` |  |
| app.trustPoints.acr | int | `25` |  |
| app.trustPoints.crossDevice | int | `30` |  |
| app.trustPoints.email | int | `20` |  |
| app.trustPoints.firstDevice | int | `30` |  |
| autoscaling.enabled | bool | `false` |  |
| autoscaling.maxReplicas | int | `5` |  |
| autoscaling.minReplicas | int | `1` |  |
| autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| database.cnpg.backup.enabled | bool | `false` |  |
| database.cnpg.database | string | `"devicedb"` |  |
| database.cnpg.instances | int | `1` |  |
| database.cnpg.password | string | `""` |  |
| database.cnpg.postgresql.parameters | object | `{}` |  |
| database.cnpg.resources | object | `{}` |  |
| database.cnpg.storage.size | string | `"5Gi"` |  |
| database.cnpg.storage.storageClass | string | `""` |  |
| database.cnpg.username | string | `"device"` |  |
| database.cnpg.walStorage.enabled | bool | `false` |  |
| database.cnpg.walStorage.size | string | `"1Gi"` |  |
| database.cnpg.walStorage.storageClass | string | `""` |  |
| database.external.enabled | bool | `false` |  |
| database.external.url | string | `"postgres://device:device@external-postgres:5432/devicedb?sslmode=require"` |  |
| frontend.apiUrl | string | `""` |  |
| frontend.enabled | bool | `true` |  |
| frontend.exampleApiUrl | string | `""` |  |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/ia-generative/aigis"` |  |
| image.tag | string | `""` |  |
| imagePullSecrets | list | `[]` |  |
| ingress.annotations | object | `{}` |  |
| ingress.className | string | `""` |  |
| ingress.enabled | bool | `false` |  |
| ingress.hosts[0].host | string | `"device-service.local"` |  |
| ingress.hosts[0].paths[0].path | string | `"/"` |  |
| ingress.hosts[0].paths[0].pathType | string | `"Prefix"` |  |
| ingress.tls | list | `[]` |  |
| migrations.annotations."helm.sh/hook" | string | `"pre-install,pre-upgrade"` |  |
| migrations.annotations."helm.sh/hook-delete-policy" | string | `"before-hook-creation,hook-succeeded"` |  |
| migrations.annotations."helm.sh/hook-weight" | string | `"0"` |  |
| migrations.enabled | bool | `true` |  |
| migrations.image.pullPolicy | string | `"IfNotPresent"` |  |
| migrations.image.repository | string | `"postgres"` |  |
| migrations.image.tag | string | `"16-alpine"` |  |
| migrations.resources | object | `{}` |  |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| podSecurityContext.fsGroup | int | `65532` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.runAsUser | int | `65532` |  |
| redis.external.enabled | bool | `false` |  |
| redis.external.url | string | `"redis://my-redis:6379"` |  |
| replicaCount | int | `1` |  |
| resources.limits.cpu | string | `"500m"` |  |
| resources.limits.memory | string | `"256Mi"` |  |
| resources.requests.cpu | string | `"100m"` |  |
| resources.requests.memory | string | `"128Mi"` |  |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| service.port | int | `8080` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| serviceMonitor.enabled | bool | `true` |  |
| serviceMonitor.interval | string | `"30s"` |  |
| serviceMonitor.labels | object | `{}` |  |
| serviceMonitor.path | string | `"/metrics"` |  |
| serviceMonitor.scrapeTimeout | string | `""` |  |
| tolerations | list | `[]` |  |
| valkey.architecture | string | `"standalone"` |  |
| valkey.auth.enabled | bool | `false` |  |
| valkey.enabled | bool | `true` |  |
| valkey.primary.extraFlags[0] | string | `"--appendonly yes"` |  |
| valkey.primary.persistence.enabled | bool | `true` |  |
| valkey.primary.persistence.size | string | `"1Gi"` |  |
| valkey.primary.persistence.storageClass | string | `""` |  |
| valkey.primary.resources.limits.cpu | string | `"250m"` |  |
| valkey.primary.resources.limits.memory | string | `"128Mi"` |  |
| valkey.primary.resources.requests.cpu | string | `"50m"` |  |
| valkey.primary.resources.requests.memory | string | `"64Mi"` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)

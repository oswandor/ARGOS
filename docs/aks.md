# ARGOS en Azure Kubernetes Service (AKS)

Guía de despliegue y análisis de compatibilidad. **No está probada contra una suscripción Azure
real**: los comandos son el punto de partida, no una receta verificada. Ajusta nombres, región,
SKUs y red a tu entorno.

## 0. Respuesta corta

**El sandbox no funciona tal cual en AKS.**

- AKS usa **containerd**, no Docker. No existe `/var/run/docker.sock` en el nodo.
- El servicio `sandbox-runner` actual habla con el **daemon de Docker** (`docker.from_env()`), así
  que en AKS falla al arrancar cualquier worker.
- Montar un Docker-in-Docker privilegiado para conservarlo está bloqueado por *Pod Security
  Standards* de AKS y no es una buena idea: los workers de parseo comparten kernel con el nodo.

**Qué sí funciona sin cambios:** la API, PostgreSQL, CrewAI, el registry de herramientas, los
5 workers (imágenes), los informes y el contrato `result.json`.

**Qué hay que cambiar:** la forma de lanzar el worker. Dos caminos:

| Opción | Cambio de código | Cuándo |
| --- | --- | --- |
| **A. Runner sobre Kubernetes Jobs** (recomendado) | Sí: reescribir `runner/` para crear `Job` en vez de contenedores Docker | Quieres todo en AKS y aislamiento nativo |
| **B. Sandbox fuera de AKS** (rápido) | No | Quieres AKS ya y mantener el sandbox en una VM |
| C. Docker-in-Docker privilegiado | Sí, y es inseguro | **No recomendado**; AKS lo bloquea |

---

## 1. Qué cambia respecto a Docker Compose

| Pieza | Docker Compose (hoy) | AKS |
| --- | --- | --- |
| Orquestador de workers | `sandbox-runner` + Docker SDK | Runner + **Kubernetes Jobs** |
| Aislamiento de red | `--network none` | **NetworkPolicy deny-all** (el pod siempre tiene netns; no hay `none` literal) |
| Socket | `/var/run/docker.sock` en el runner | **No existe**; el runner usa la API de Kubernetes con RBAC |
| Muestras/artefactos | volúmenes Docker efímeros | **PVC Azure Files RWX** (`/data/samples`, `/data/results`) |
| Límites | flags de `docker run` | `resources`, `activeDeadlineSeconds`, `pids` no nativo (usar límites de nodo) |
| PostgreSQL | contenedor Compose | **Azure Database for PostgreSQL Flexible Server** (recomendado) o StatefulSet |
| Informes | bind mount `./reports` | PVC o Blob; la API ya devuelve el informe por HTTP |
| Ingress | ninguno (127.0.0.1) | NGINX/App Gateway + TLS; **timeouts > 60 s** o usar `wait=false` |
| Secretos | `.env.docker` | `Secret` de Kubernetes (o Key Vault CSI) |

El contrato interno **no cambia**: la API sigue llamando `POST /v1/run` al runner y recibiendo
`result.json` con `findings`, `artifacts`, `data`, `engines`. Solo cambia la implementación del
runner.

---

## 2. Arquitectura objetivo (opción A)

```
Ingress (TLS)
   │
   ▼
argos-api (Deployment, 1..N réplicas, sin socket)
   ├── argos-postgres (StatefulSet o Flexible Server)
   ├── PVC argos-data (Azure Files RWX)
   └── HTTP interno → argos-sandbox-runner (Service, ClusterIP)
                          │  ServiceAccount + Role (batch/jobs)
                          ▼
                    Job efímero por herramienta
                    pod worker-pdf/office/js/binary/yara
                    NetworkPolicy: deny-all ingress/egress
                    securityContext: non-root, RO rootfs, drop ALL
```

---

## 3. Requisitos

- `az` CLI, `kubectl`, `helm` (opcional para ingress-nginx).
- Suscripción con cuota para AKS + ACR + PostgreSQL.
- `kubectl` conectado al clúster (`az aks get-credentials`).
- Imágenes Linux `amd64` (los workers son Linux).

Variables de trabajo (PowerShell):

```powershell
$RG       = "rg-argos"
$LOCATION = "eastus2"
$ACR      = "argosacr$((Get-Random -Maximum 99999))"
$AKS      = "aks-argos"
$NS       = "argos"
```

---

## 4. Paso a paso (opción A: Jobs nativos)

### 4.1 Grupo de recursos y ACR

```powershell
az group create -n $RG -l $LOCATION
az acr create -g $RG -n $ACR --sku Basic --admin-enabled false
```

### 4.2 Construir y subir imágenes

Desde la raíz del repositorio. ACR Tasks construye en la nube (no requiere Docker local):

```powershell
az acr build -r $ACR -t "argos/api:0.2.0" -f docker/api.Dockerfile .
az acr build -r $ACR -t "argos/worker-base:0.1.0" -f docker/worker-base.Dockerfile .
$BASE = "$ACR.azurecr.io/argos/worker-base:0.1.0"
foreach ($f in @("pdf","office","js","binary","yara")) {
  az acr build -r $ACR -t "argos/worker-$f`:0.1.0" `
    --build-arg "BASE_IMAGE=$BASE" `
    -f "docker/worker-$f.Dockerfile" .
}
az acr build -r $ACR -t "argos/sandbox-runner-k8s:0.1.0" -f docker/runner-k8s.Dockerfile .
```

> Los Dockerfiles de worker usan `ARG BASE_IMAGE=argos/worker-base:0.1.0`; en ACR hay que pasar
> `--build-arg BASE_IMAGE=$ACR.azurecr.io/...`. Si no, el build busca la base en Docker Hub.
>
> `docker/runner-k8s.Dockerfile` **no existe todavía**: es parte del cambio de código de la
> sección 5. Hasta implementarlo, usa la opción B.

### 4.3 Crear AKS

```powershell
az aks create -g $RG -n $AKS -l $LOCATION `
  --node-count 2 --node-vm-size Standard_D4s_v5 `
  --network-plugin azure --network-policy calico `
  --enable-managed-identity --generate-ssh-keys `
  --enable-cluster-autoscaler --min-count 2 --max-count 6

az aks update -g $RG -n $AKS --attach-acr $ACR
az aks get-credentials -g $RG -n $AKS --overwrite-existing
```

> Si tu suscripción usa *Azure CNI powered by Cilium*, cambia `--network-policy calico` por el
> flag equivalente de Cilium. La NetworkPolicy del paso 4.8 es imprescindible.

Nodo pool dedicado para workers (opcional pero recomendado):

```powershell
az aks nodepool add -g $RG --cluster-name $AKS -n sandbox `
  --node-count 2 --node-vm-size Standard_D4s_v5 `
  --labels workload=sandbox --node-taints workload=sandbox:NoSchedule
```

Los `Job` de worker deben llevar la tolerancia `workload=sandbox:NoSchedule` y el nodeSelector
`workload: sandbox`.

### 4.4 Namespace, PVC y secretos

```powershell
kubectl create namespace $NS
```

`argos-storage.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: argos-data
  namespace: argos
spec:
  accessModes: ["ReadWriteMany"]
  storageClassName: azurefile-csi
  resources:
    requests:
      storage: 50Gi
```

> `azurefile-csi` es SMB y soporta RWX. Si tu clúster solo tiene `managed-csi` (discos, RWO),
> cambia a `ReadWriteOnce` y mantén API y runner en el mismo nodo, o usa Blob CSI.

```powershell
kubectl apply -f argos-storage.yaml
```

Secretos (no los pongas en el YAML):

```powershell
$PGPASS = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | % {[char]$_})
$RUNNER = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 48 | % {[char]$_})
kubectl -n $NS create secret generic argos-secrets `
  --from-literal=POSTGRES_PASSWORD="$PGPASS" `
  --from-literal=DATABASE_URL="postgresql+psycopg://argos:$PGPASS@argos-postgres:5432/argos" `
  --from-literal=DEEPSEEK_API_KEY="sk-..." `
  --from-literal=RUNNER_SHARED_TOKEN="$RUNNER" `
  --from-literal=API_KEY=""
```

### 4.5 PostgreSQL

Para laboratorio, StatefulSet con PVC:

```yaml
apiVersion: v1
kind: Service
metadata: {name: argos-postgres, namespace: argos}
spec:
  selector: {app: argos-postgres}
  ports: [{port: 5432, targetPort: 5432}]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: argos-postgres, namespace: argos}
spec:
  serviceName: argos-postgres
  replicas: 1
  selector: {matchLabels: {app: argos-postgres}}
  template:
    metadata: {labels: {app: argos-postgres}}
    spec:
      securityContext: {fsGroup: 999}
      containers:
        - name: postgres
          image: postgres:16
          env:
            - {name: POSTGRES_DB, value: argos}
            - {name: POSTGRES_USER, value: argos}
            - name: POSTGRES_PASSWORD
              valueFrom: {secretKeyRef: {name: argos-secrets, key: POSTGRES_PASSWORD}}
          ports: [{containerPort: 5432}]
          volumeMounts: [{name: pgdata, mountPath: /var/lib/postgresql/data}]
          resources:
            requests: {cpu: 250m, memory: 512Mi}
            limits: {cpu: "1", memory: 1Gi}
  volumeClaimTemplates:
    - metadata: {name: pgdata}
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: managed-csi
        resources: {requests: {storage: 20Gi}}
```

**Producción:** usa Azure Database for PostgreSQL Flexible Server con Private Link; cambia el
`DATABASE_URL` del secreto y elimina este StatefulSet. Requiere VNet delegada, DNS privado y
reglas de firewall; no lo cubre esta guía paso a paso.

> El StatefulSet de laboratorio arranca el entrypoint de PostgreSQL como root para inicializar el
> volumen. Un namespace con Pod Security `restricted` lo rechazará: allí usa PostgreSQL gestionado
> o un namespace separado sin esa etiqueta.

### 4.6 API

`argos-api.yaml` (resumen; ajusta la imagen a `<ACR>.azurecr.io/argos/api:0.2.0`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: argos-api, namespace: argos}
spec:
  replicas: 1
  selector: {matchLabels: {app: argos-api}}
  template:
    metadata: {labels: {app: argos-api}}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10000
        runAsGroup: 10000
        fsGroup: 10000
        fsGroupChangePolicy: OnRootMismatch
      containers:
        - name: api
          image: <ACR>.azurecr.io/argos/api:0.2.0
          ports: [{containerPort: 8000}]
          envFrom:
            - configMapRef: {name: argos-config}
          env:
            - name: HOME
              value: /tmp
            - name: DEEPSEEK_API_KEY
              valueFrom: {secretKeyRef: {name: argos-secrets, key: DEEPSEEK_API_KEY}}
            - name: DATABASE_URL
              valueFrom: {secretKeyRef: {name: argos-secrets, key: DATABASE_URL}}
            - name: RUNNER_SHARED_TOKEN
              valueFrom: {secretKeyRef: {name: argos-secrets, key: RUNNER_SHARED_TOKEN}}
          volumeMounts:
            - {name: data, mountPath: /data}
            - {name: tmp, mountPath: /tmp}
          readinessProbe:
            httpGet: {path: /health, port: 8000}
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            httpGet: {path: /health, port: 8000}
            initialDelaySeconds: 30
            periodSeconds: 30
          resources:
            requests: {cpu: 500m, memory: 1Gi}
            limits: {cpu: "2", memory: 2Gi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
            seccompProfile: {type: RuntimeDefault}
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: argos-data}
        - name: tmp
          emptyDir: {sizeLimit: 256Mi}
---
apiVersion: v1
kind: Service
metadata: {name: argos-api, namespace: argos}
spec:
  selector: {app: argos-api}
  ports: [{port: 80, targetPort: 8000}]
```

`argos-config`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata: {name: argos-config, namespace: argos}
data:
  EXECUTOR: "runner"
  SANDBOX_RUNNER_URL: "http://argos-sandbox-runner:8081"
  DATA_DIR: "/data"
  CREW_ENABLED: "true"
  CREW_MODEL: "deepseek-chat"
  CREW_VERBOSE: "true"
  MAX_UPLOAD_MB: "50"
  STRICT_PRIVACY: "true"
```

> `readOnlyRootFilesystem: true` puede requerir montar `/tmp` (ya incluido). Si la API escribe
> algo más en el rootfs, revisa logs y añade `emptyDir`.

### 4.7 Runner sobre Kubernetes (cambio de código)

`runner/main.py` deja de usar `docker` y usa el cliente `kubernetes`:

```python
from kubernetes import client, config, watch

config.load_incluster_config()
batch = client.BatchV1Api()

job = batch.create_namespaced_job(namespace, {
    "metadata": {"generateName": "argos-worker-", "labels": {"argos.io/role": "worker"}},
    "spec": {
        "backoffLimit": 0,
        "activeDeadlineSeconds": req.timeout_s + 30,
        "ttlSecondsAfterFinished": 300,
        "template": {
            "metadata": {"labels": {"argos.io/role": "worker"}},
            "spec": {
                "restartPolicy": "Never",
                "automountServiceAccountToken": False,
                "nodeSelector": {"workload": "sandbox"},
                "tolerations": [{"key": "workload", "value": "sandbox", "effect": "NoSchedule"}],
                "securityContext": {
                    "runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                    "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [{
                    "name": "worker",
                    "image": image,
                    "command": ["python", "/opt/argos/entry.py", tool,
                                f"/data/samples/{job_id}/sample.bin", "--type", tipo,
                                "--out", f"/data/results/{job_id}"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "resources": {"requests": {"cpu": "500m", "memory": "512Mi"},
                                  "limits": {"cpu": "1", "memory": "768Mi"}},
                    "volumeMounts": [
                        {"name": "data", "mountPath": "/data"},
                        {"name": "tmp", "mountPath": "/tmp"},
                    ],
                }],
                "volumes": [
                    {"name": "data", "persistentVolumeClaim": {"claimName": "argos-data"}},
                    {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                ],
            },
        },
    },
})
```

Flujo del nuevo runner:

1. Escribe `/data/samples/<job_id>/sample.bin` en el PVC (pertenece al runner, uid 10000).
2. Crea el `Job` con subPath `/data` completo (más simple que subPath por job) y `--out`
   `/data/results/<job_id>`.
3. Espera (`watch`) a `Complete`/`Failed` con timeout.
4. Lee `/data/results/<job_id>/result.json` y los artefactos; valida tamaño y nombres.
5. Borra el `Job` (o deja que `ttlSecondsAfterFinished` lo haga) y limpia el directorio.

El contrato HTTP con la API **no cambia** (`POST /v1/run` → JSON con `findings`, `artifacts`,
`data`, `engines`).

RBAC mínimo del runner:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: {name: argos-runner, namespace: argos}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: argos-runner, namespace: argos}
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: argos-runner, namespace: argos}
subjects:
  - {kind: ServiceAccount, name: argos-runner, namespace: argos}
roleRef: {kind: Role, name: argos-runner, apiGroup: rbac.authorization.k8s.io}
```

Deployment y Service del runner (imagen nueva, sin socket):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: argos-sandbox-runner, namespace: argos}
spec:
  replicas: 1
  selector: {matchLabels: {app: argos-sandbox-runner}}
  template:
    metadata: {labels: {app: argos-sandbox-runner}}
    spec:
      serviceAccountName: argos-runner
      securityContext: {runAsNonRoot: true, runAsUser: 10000, fsGroup: 10000}
      containers:
        - name: runner
          image: <ACR>.azurecr.io/argos/sandbox-runner-k8s:0.1.0
          ports: [{containerPort: 8081}]
          env:
            - {name: NAMESPACE, value: argos}
            - {name: WORKER_IMAGE_PREFIX, value: "<ACR>.azurecr.io/argos/worker"}
            - {name: WORKER_IMAGE_TAG, value: "0.1.0"}
            - {name: WORKER_RESULTS_PVC, value: "argos-data"}
            - name: RUNNER_SHARED_TOKEN
              valueFrom: {secretKeyRef: {name: argos-secrets, key: RUNNER_SHARED_TOKEN}}
          volumeMounts:
            - {name: data, mountPath: /data}
            - {name: tmp, mountPath: /tmp}
          readinessProbe:
            httpGet: {path: /ready, port: 8081}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
            seccompProfile: {type: RuntimeDefault}
          resources:
            requests: {cpu: 250m, memory: 512Mi}
            limits: {cpu: "1", memory: 1Gi}
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: argos-data}
        - name: tmp
          emptyDir: {sizeLimit: 128Mi}
---
apiVersion: v1
kind: Service
metadata: {name: argos-sandbox-runner, namespace: argos}
spec:
  selector: {app: argos-sandbox-runner}
  ports: [{port: 8081, targetPort: 8081}]
```

El runner necesita crear `Job` en el mismo namespace y leer/escribir el PVC; no necesita el socket
de Docker ni `pods/exec`.

### 4.8 NetworkPolicy para workers

El equivalente a `--network none` es denegar todo el tráfico del pod:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: argos-worker-deny-all, namespace: argos}
spec:
  podSelector:
    matchLabels: {argos.io/role: worker}
  policyTypes: ["Ingress", "Egress"]
  ingress: []
  egress: []
```

- El montaje de Azure Files lo hace el CSI/kubelet desde el nodo, no el pod; normalmente no lo
  bloquea. **Pruébalo**: si el worker no ve `/data`, añade una excepción de egreso a la IP del
  storage account (SMB 445) o usa un CSI que monte por virtiofs.
- Los workers no necesitan DNS ni ServiceAccount (`automountServiceAccountToken: false`).
- No hay `network=none` literal: el pod conserva loopback y netns, pero sin rutas permitidas.

### 4.9 Ingress y TLS

Instala ingress-nginx (o usa AGIC) y aplica:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argos
  namespace: argos
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "60m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["argos.example.com"]
      secretName: argos-tls
  rules:
    - host: argos.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: {name: argos-api, port: {number: 80}}
```

> Un análisis con crew tarda ~40 s y el sandbox puede sumar. Si el ingress corta a los 30 s,
> usa `wait=false` y consulta el estado, o sube los timeouts.

### 4.10 Validación

```powershell
kubectl -n argos get pods,svc,jobs
kubectl -n argos port-forward svc/argos-api 8000:8000
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/sandbox-status
```

Subida asíncrona y seguimiento de Jobs:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/malware-samples" -F "file=@muestra.pdf"
kubectl -n argos get jobs,pods -w
curl.exe http://127.0.0.1:8000/malware-samples/<id>/analysis-report
```

Checklist:

- [ ] `/health` con `database=ok` y `runner.available=true`.
- [ ] `/sandbox-status` lista las 5 imágenes (configuradas/verificadas).
- [ ] Un análisis benigno crea un `Job`, termina y deja el informe.
- [ ] Los `Job` se borran solos (`ttlSecondsAfterFinished`).
- [ ] Un pod worker no tiene salida a Internet (test con `kubectl run` etiquetado `worker`).
- [ ] El PVC conserva muestras tras reiniciar la API.
- [ ] Los logs muestran la traza de agentes (`CREW_VERBOSE=true`).

---

## 5. Cambios de código necesarios (opción A)

| Archivo | Cambio | Esfuerzo |
| --- | --- | --- |
| `runner/main.py` | Docker SDK → `kubernetes` client; crear `Job`, esperar, leer PVC, borrar | ~300–400 líneas |
| `docker/runner-k8s.Dockerfile` | Imagen con `kubernetes` en vez de `docker` | 1 archivo |
| `tools/executors/runner_exec.py` | **Sin cambios** (mismo contrato HTTP) | 0 |
| `workers/entry.py` | **Sin cambios** (`/work` pasa a `/data/samples/<id>`) | 0 |
| `core/settings.py` | Opcional: `K8S_NAMESPACE`, `WORKER_RESULTS_PVC`, `WORKER_NODE_SELECTOR` | pequeño |
| `api/routes/meta.py` | `/sandbox-status` interpreta el nuevo `/health` del runner (imágenes configuradas vs verificadas) | pequeño |
| `deploy/k8s/*.yaml` | Manifiestos nuevos (este documento) | — |

**Lo que no hay que tocar:** agentes CrewAI, scoring, adaptadores, informes, API, esquema de BD,
imágenes de workers, contrato `result.json`.

Riesgos a cubrir en la implementación:

- Limpieza de PVC si el `Job` falla antes de escribir (el runner borra el directorio).
- Concurrencia: nombre de `Job` único (`generateName`), no reutilizar directorios.
- Tamaño de artefactos: mismos límites que hoy (`max_artifact_bytes`).
- `fsGroup` y permisos: el PVC lo escribe el runner (uid 10000) y lo lee/escribe el worker
  (uid 10001); usa directorios `0777` para resultados o un `initContainer` que ajuste permisos.
- Si el pod de la API muere, `BackgroundTasks` pierde la investigación en curso. En AKS con
  varias réplicas, mueve el análisis a un `Job` o a Celery.

---

## 6. Opción B: sandbox fuera de AKS (sin tocar código)

La API va a AKS y el sandbox sigue en una VM con Docker Compose.

1. VM Linux en la misma VNet (o conectada por VPN/peering), con Docker y el repo.
2. En la VM: `.\docker\up.ps1` (o solo `docker compose up sandbox-runner` + workers).
3. En AKS, configura la API:

```yaml
SANDBOX_RUNNER_URL: "http://10.0.1.4:8081"   # IP privada de la VM
EXECUTOR: "runner"
RUNNER_SHARED_TOKEN: "<el mismo de la VM>"
```

4. NSG: permite 8081 **solo** desde la subred de pods de AKS; nada desde Internet.
5. La API no necesita Docker; el runner de la VM sigue usando el socket local.

Ventajas: cero cambios de código, sandbox probado. Desventajas: una VM más que parchear y
proteger; el runner sigue siendo un host Docker.

---

## 7. Opción C: Docker-in-Docker (no recomendado)

- AKS no expone el socket de Docker del nodo (containerd).
- DinD exige `privileged: true` y un daemon anidado; *Pod Security Standards* `baseline`/
  `restricted` lo rechazan.
- Aunque funcionara, el worker seguiría compartiendo kernel con el nodo; el aislamiento no mejora
  y añades complejidad.
- Si necesitas aislamiento fuerte, usa **Pod Sandboxing (Kata)** o **gVisor** en un node pool
  dedicado, no DinD.

---

## 8. Seguridad en AKS

- Namespace con `pod-security.kubernetes.io/enforce: restricted` (los manifiestos cumplen:
  non-root, RO rootfs, drop ALL, seccomp RuntimeDefault).
- Workers en node pool dedicado con taint; sin ServiceAccount token; NetworkPolicy deny-all.
- Secretos en `Secret` (mejor: Key Vault + CSI driver + Workload Identity).
- Ingress con TLS; `API_KEY` para autenticar; `wait=false` para no bloquear el ingress.
- No montar el socket de containerd/Docker en ningún pod.
- AKS comparte kernel: para muestras de origen desconocido, Kata/gVisor o un clúster dedicado
  desechable.
- Limita `MAX_UPLOAD_MB`, `activeDeadlineSeconds`, cuotas de PVC y `ResourceQuota` del namespace.

---

## 9. Dimensionamiento orientativo

| Componente | Requests | Límites | Réplicas |
| --- | --- | --- | --- |
| API | 500m / 1Gi | 2 CPU / 2Gi | 1–2 |
| Runner | 250m / 512Mi | 1 CPU / 1Gi | 1 |
| Worker (Job) | 500m / 512Mi | 1 CPU / 768Mi | efímero |
| PostgreSQL (lab) | 250m / 512Mi | 1 CPU / 1Gi | 1 |
| PVC | — | 50Gi Azure Files | — |

Coste: AKS (nodos), ACR Basic, Azure Files y PostgreSQL. No incluyas cifras fijas: depende de
región, horas y SKU. Para laboratorio, `--enable-cluster-autoscaler` y apagar el clúster fuera de
horario ahorra la mayor parte.

---

## 10. Operación

```powershell
kubectl -n argos logs deploy/argos-api -f
kubectl -n argos get jobs,pods
kubectl -n argos describe job <job>
kubectl -n argos delete job <job>
kubectl -n argos rollout restart deploy/argos-api
```

- Actualizar imágenes: `az acr build` con nuevo tag → `kubectl set image` o `rollout restart`.
- Limpieza: `ttlSecondsAfterFinished: 300`; el runner también borra el `Job` al terminar.
- Backups: PostgreSQL gestionado o `pg_dump` programado; PVC de muestras según retención.
- Logs: same as Compose; `CREW_VERBOSE=false` para reducir volumen.

---

## 11. Decisión recomendada

| Situación | Camino |
| --- | --- |
| Quieres todo en AKS y puedes invertir 1–2 días en el runner | **Opción A** |
| Necesitas AKS esta semana y el sandbox ya funciona en Docker | **Opción B** |
| Buscas aislamiento fuerte de malware | AKS + node pool Kata/gVisor (o sandbox en VM dedicada) |

**Conclusión:** el sandbox actual **no se puede desplegar tal cual** en AKS. La API, los agentes,
PostgreSQL y los informes sí. El cambio mínimo es sustituir el runner Docker por un runner que cree
`Job` de Kubernetes; el contrato interno y las imágenes de worker se reutilizan sin cambios.

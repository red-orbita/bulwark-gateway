# CI/CD Integration Guide

Guide for deploying Sentinel Gateway via enterprise CI/CD platforms.

## Table of Contents

- [Overview](#overview)
- [Pipeline Architecture](#pipeline-architecture)
- [GitHub Actions](#github-actions)
- [Jenkins](#jenkins)
- [Azure DevOps](#azure-devops)
- [GitLab CI/CD](#gitlab-cicd)
- [Tekton (Kubernetes-native)](#tekton-kubernetes-native)
- [Environment Configuration](#environment-configuration)
- [Secrets Management](#secrets-management)
- [Rollback Strategy](#rollback-strategy)

---

## Overview

All pipelines follow the same 4-stage pattern:

```
Test → Build → Deploy Staging → Deploy Production
```

| Stage | Trigger | Gate |
|-------|---------|------|
| Test | Every push/PR | Automatic |
| Build | Push to `main` or tag `v*.*.*` | Automatic |
| Deploy Staging | Push to `main` | Automatic |
| Deploy Production | Tag `v*.*.*` | Manual approval |

**Versioning:**
- Branch pushes: `sha-<8-char-commit-hash>` (e.g., `sha-a1b2c3d4`)
- Tags: semantic version without `v` prefix (e.g., `0.4.3`)

---

## Pipeline Architecture

```
┌─────────────┐    ┌─────────────┐    ┌────────────────┐    ┌──────────────────┐
│   Lint &    │    │  Build &    │    │   Deploy to    │    │   Deploy to      │
│   Test      │───>│  Push       │───>│   Staging      │───>│   Production     │
│             │    │  Images     │    │   (auto)       │    │   (manual gate)  │
└─────────────┘    └─────────────┘    └────────────────┘    └──────────────────┘
                          │                    │                       │
                          ▼                    ▼                       ▼
                   ┌─────────────┐    ┌────────────────┐    ┌──────────────────┐
                   │  Registry   │    │  Helm upgrade  │    │  Helm upgrade    │
                   │  (ACR/ECR/  │    │  + validate    │    │  + validate      │
                   │   GCR/GHCR) │    │  + smoke test  │    │  + rollback on   │
                   └─────────────┘    └────────────────┘    │    failure       │
                                                            └──────────────────┘
```

---

## GitHub Actions

**File:** `.github/workflows/deploy.yml`

### Setup

1. Create environments in GitHub (Settings > Environments):
   - `staging` — no protection rules
   - `production` — require reviewers

2. Configure secrets (Settings > Secrets > Actions):

| Secret | Description |
|--------|-------------|
| `REGISTRY_URL` | Container registry (e.g., `ghcr.io/myorg`) |
| `REGISTRY_USERNAME` | Registry username |
| `REGISTRY_PASSWORD` | Registry password/token |
| `KUBECONFIG_STAGING` | Base64-encoded kubeconfig for staging |
| `KUBECONFIG_PROD` | Base64-encoded kubeconfig for production |
| `HELM_VALUES_STAGING` | Base64-encoded `values-staging.yaml` |
| `HELM_VALUES_PROD` | Base64-encoded `values-production.yaml` |

3. Encode your values files:
```bash
cat ci/values-staging.yaml | base64 -w0  # → paste as HELM_VALUES_STAGING
cat ci/values-production.yaml | base64 -w0  # → paste as HELM_VALUES_PROD
```

### Trigger

```bash
# Deploy to staging (auto on push to main)
git push origin main

# Deploy to production
git tag v0.4.3
git push origin v0.4.3
```

---

## Jenkins

**File:** `ci/Jenkinsfile`

### Setup

1. Install required plugins:
   - Docker Pipeline
   - Kubernetes CLI
   - Pipeline Utility Steps
   - Credentials Binding

2. Configure credentials (Manage Jenkins > Credentials):

| ID | Type | Description |
|----|------|-------------|
| `registry-url` | Secret text | Container registry URL |
| `registry-credentials` | Username/Password | Registry auth |
| `kubeconfig-staging` | Secret file | Staging kubeconfig |
| `kubeconfig-production` | Secret file | Production kubeconfig |
| `helm-values-staging` | Secret file | values-staging.yaml |
| `helm-values-production` | Secret file | values-production.yaml |

3. Create a Multibranch Pipeline:
   - Source: Git repository
   - Build configuration: `ci/Jenkinsfile`
   - Scan interval: 1 minute (or use webhooks)

### Production Gate

The production stage uses `input` step requiring approval from `admin` or `deployers` group. Configure these groups in Jenkins Global Security.

---

## Azure DevOps

**File:** `ci/azure-pipelines.yml`

### Setup

1. Create service connections (Project Settings > Service connections):
   - `acr-connection` — Azure Container Registry
   - `aks-staging` — Kubernetes (staging AKS)
   - `aks-production` — Kubernetes (production AKS)

2. Create variable group `sentinel-gateway-vars`:
   - `REGISTRY_URL` — e.g., `myregistry.azurecr.io`
   - `BACKEND_IP` — LLM backend IP

3. Upload secure files (Pipelines > Library > Secure files):
   - `values-staging.yaml`
   - `values-production.yaml`

4. Configure environments with approval gates:
   - `staging` — no approval needed
   - `production` — require approval from designated users

5. Create pipeline:
   - Pipelines > New Pipeline > Azure Repos Git / GitHub
   - Existing YAML: `ci/azure-pipelines.yml`

### Trigger

Pipeline triggers automatically on push to `main` or tag creation.

---

## GitLab CI/CD

**File:** `ci/.gitlab-ci.yml`

### Setup

1. Configure CI/CD variables (Settings > CI/CD > Variables):

| Variable | Protected | Masked | Description |
|----------|-----------|--------|-------------|
| `REGISTRY_URL` | No | No | Registry URL |
| `REGISTRY_USER` | No | No | Registry username |
| `REGISTRY_PASSWORD` | Yes | Yes | Registry password |
| `KUBECONFIG_STAGING` | No | No | Base64 kubeconfig |
| `KUBECONFIG_PROD` | Yes | No | Base64 kubeconfig (protected) |

2. Configure environments (Deployments > Environments):
   - `staging` — auto deploy
   - `production` — require manual action (configured via `when: manual`)

3. Place the file at repository root or set CI config path:
   - Settings > CI/CD > General pipelines > CI/CD configuration file: `ci/.gitlab-ci.yml`

### Trigger

```bash
# Auto-deploy to staging
git push origin main

# Deploy to production (creates tag, then manual click in UI)
git tag v0.4.3
git push origin v0.4.3
# → Go to CI/CD > Pipelines > click "Deploy Production" play button
```

---

## Tekton (Kubernetes-native)

**File:** `ci/tekton/pipeline.yaml`

### Setup

1. Install Tekton Pipelines:
```bash
kubectl apply -f https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
```

2. Install required ClusterTasks:
```bash
# git-clone task
kubectl apply -f https://raw.githubusercontent.com/tektoncd/catalog/main/task/git-clone/0.9/git-clone.yaml
# kaniko build task
kubectl apply -f https://raw.githubusercontent.com/tektoncd/catalog/main/task/kaniko/0.6/kaniko.yaml
```

3. Create secrets and ConfigMaps:
```bash
# Registry credentials
kubectl create secret docker-registry registry-credentials \
  --docker-server=<REGISTRY_URL> \
  --docker-username=<USER> \
  --docker-password=<PASS> \
  -n tekton-pipelines

# Helm values
kubectl create configmap sentinel-gateway-helm-values \
  --from-file=values-staging.yaml=ci/values-staging.yaml \
  --from-file=values-production.yaml=ci/values-production.yaml \
  -n tekton-pipelines
```

4. Create deployer ServiceAccount with RBAC:
```bash
kubectl create sa tekton-deployer -n tekton-pipelines
kubectl create clusterrolebinding tekton-deployer \
  --clusterrole=cluster-admin \
  --serviceaccount=tekton-pipelines:tekton-deployer
```

5. Apply the pipeline:
```bash
kubectl apply -f ci/tekton/pipeline.yaml
```

### Trigger

```bash
# Manual PipelineRun
kubectl create -f ci/tekton/pipeline.yaml  # Uses the PipelineRun at the bottom

# Or with Tekton CLI
tkn pipeline start sentinel-gateway-deploy \
  --param git-url=https://github.com/myorg/sentinel-gateway.git \
  --param git-revision=main \
  --param image-registry=myregistry.azurecr.io \
  --param target-environment=staging \
  --param version=0.4.3 \
  --workspace name=source,claimName=tekton-source-pvc \
  --workspace name=docker-credentials,secret=registry-credentials \
  --workspace name=helm-values,config=sentinel-gateway-helm-values
```

For automated triggers, install [Tekton Triggers](https://tekton.dev/docs/triggers/) and configure a webhook EventListener.

---

## Environment Configuration

### Values Files

The `ci/` directory contains template values files:

| File | Purpose |
|------|---------|
| `ci/values-staging.yaml` | Staging overrides (2 replicas, internal Redis, debug logging) |
| `ci/values-production.yaml` | Production overrides (3+ replicas, external Redis, minimal logging) |

Copy and customize these for your environment. Sensitive values (passwords, keys) should be injected via `--set` from CI/CD secrets — never committed to the repository.

### Required --set Overrides (per environment)

These must always be passed via CI/CD pipeline secrets:

```bash
--set backend.ip=<BACKEND_IP>
--set proxy.image.tag=<VERSION>
--set admin.image.tag=<VERSION>
# If using external Redis:
--set externalRedis.host=<REDIS_HOST>
```

---

## Secrets Management

### Recommended Pattern

| Approach | Platforms | Description |
|----------|-----------|-------------|
| CI/CD native secrets | All | Store in platform's secret store (GitHub Secrets, Jenkins Credentials, Azure Key Vault, GitLab Variables) |
| External Secrets Operator | Kubernetes | Sync secrets from Vault/AWS SM/Azure KV into K8s Secrets automatically |
| Sealed Secrets | Kubernetes | Encrypt secrets in Git (safe to commit), decrypted by controller in cluster |
| HashiCorp Vault | All | Centralized secret management with dynamic credentials |

### Secrets Required

| Secret | Used By | How to Provide |
|--------|---------|----------------|
| Redis password | Proxy, Admin | `externalRedis.existingSecret` or `--set externalRedis.password` |
| JWT secret | Proxy | Auto-generated by Helm (or `--set secrets.jwtSecret`) |
| Admin password | Admin | Auto-generated by Helm (or `--set secrets.adminPassword`) |
| API keys | Proxy | Auto-generated by Helm (or `--set secrets.apiKey`) |
| Registry credentials | CI/CD | Platform-specific (service connection, credential binding) |
| Kubeconfig | CI/CD | Platform-specific (service account, service connection) |

---

## Rollback Strategy

All pipelines support automatic rollback on deployment failure:

```bash
# Manual rollback (any platform)
helm rollback sentinel-gateway --namespace sentinel-gateway --wait

# Rollback to specific revision
helm rollback sentinel-gateway 3 --namespace sentinel-gateway --wait

# View revision history
helm history sentinel-gateway --namespace sentinel-gateway
```

### Automatic Rollback

- **Jenkins**: Configured in `post { failure { } }` block — runs `helm rollback` on deploy failure
- **Azure DevOps**: Configured in `on: failure:` strategy step
- **GitHub Actions / GitLab**: Add rollback step in job failure condition
- **Tekton**: Add a `finally` task to the pipeline

### Canary / Blue-Green

For advanced deployment strategies, consider:
- [Argo Rollouts](https://argoproj.github.io/rollouts/) — progressive delivery with automatic rollback
- [Flagger](https://flagger.app/) — Canary deployments with Istio/Nginx

These integrate with the Helm chart without modifications — just wrap the Deployment with a Rollout resource.

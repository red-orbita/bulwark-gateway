# Deploy Bulwark Gateway with ArgoCD (GitOps)

Declarative, pull-based deployment. ArgoCD keeps the cluster in sync with this
Git repo. Two Applications:

| Application | File | What it does | Sync wave |
|-------------|------|--------------|-----------|
| `bulwark-secrets` | `bulwark-secrets.yaml` | Applies the SealedSecret CRs | `-1` (first) |
| `bulwark-gateway` | `bulwark-gateway.yaml` | Deploys the Helm chart (`secrets.create=false`) | `0` (after) |

## Why `secrets.create=false`

The chart normally auto-generates secrets and uses Helm `lookup` to keep them
stable across `helm upgrade`. **ArgoCD renders with client-side `helm template`,
where `lookup` returns nothing** — so it would regenerate random JWT/passwords/
API keys on every sync (permanent `OutOfSync` drift + credential rotation).

In GitOps mode the chart creates **no** Secret objects; secrets are owned
externally. Here we use [SealedSecrets](https://github.com/bitnami-labs/sealed-secrets)
(already used by the Kustomize path in `k8s/secrets/`).

## Prerequisites

1. **ArgoCD** installed in the cluster (namespace `argocd`).
2. **SealedSecrets controller** installed in the target cluster:
   ```bash
   helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
   helm install sealed-secrets sealed-secrets/sealed-secrets -n kube-system
   ```
3. **`kubeseal`** CLI installed locally.
4. Images pushed to a registry ArgoCD's cluster can pull (see main README).

## IMPORTANT: SealedSecrets are per-cluster

`k8s/secrets/sealed-secrets.yaml` is encrypted with **one cluster's** public key
and **only decrypts in that cluster**. The committed file will NOT work in your
cluster — you must regenerate it against your own SealedSecrets controller.

## Steps

```bash
# 1. Generate plaintext secret files locally (never committed; in .gitignore)
./secrets/init.sh

# 2. Seal them with YOUR cluster's public key (covers every key the chart needs)
NAMESPACE=bulwark-gateway ./k8s/secrets/generate-sealed-secrets.sh

# 3. Commit the regenerated sealed secrets (encrypted — safe to commit)
git add k8s/secrets/sealed-secrets.yaml
git commit -m "chore: seal secrets for <cluster-name>"
git push

# 4. Edit the two Application manifests for your environment:
#    - repoURL         -> your fork/mirror (if not red-orbita/bulwark-gateway)
#    - targetRevision  -> branch or tag to track (e.g. v1.0.0 or main)
#    - backend.ip      -> your LLM backend IP
#    - *.image.*       -> your registry/repository/tag
#    (deploy/argocd/bulwark-secrets.yaml, deploy/argocd/bulwark-gateway.yaml)

# 5. Register the Applications with ArgoCD
kubectl apply -f deploy/argocd/bulwark-secrets.yaml
kubectl apply -f deploy/argocd/bulwark-gateway.yaml

# 6. Watch them converge
argocd app get bulwark-secrets
argocd app get bulwark-gateway   # -> Synced, Healthy
```

## Ordering

Sync-waves order resources **within** an App-of-Apps. As two standalone
Applications the exact order is not enforced, but it self-heals: if the Helm
pods start before the derived Secrets exist, they retry
(`CreateContainerConfigError`) until the controller creates them. To enforce
strict ordering, wrap both under an App-of-Apps parent Application.

## Rotating secrets

```bash
./secrets/init.sh --force                                   # new values
NAMESPACE=bulwark-gateway ./k8s/secrets/generate-sealed-secrets.sh
git commit -am "chore: rotate secrets" && git push          # ArgoCD applies
```

## Alternative: External Secrets Operator

If you keep secrets in Azure Key Vault / AWS Secrets Manager / Vault, replace
the `bulwark-secrets` Application with `ExternalSecret` CRs that materialize the
same Secret names (`bulwark-proxy-secrets`, `bulwark-admin-secrets`,
`bulwark-redis-secrets`, and `bulwark-monitoring-secrets` if monitoring is on).
Keep `secrets.create=false`.

# Deploying Link

The Link server is one container that serves the API **and** the built web SPA.
Two supported targets: **docker-compose** (single host) and **Kubernetes / k0s**.

> **Single instance by design.** SQLite + local-disk blobs, and the one-time
> view-consume is atomic within one process. Run exactly **one** replica on the
> data volume. Scaling out needs Postgres + object storage (separate work).

---

## Option A — docker-compose (single host)

From the repo root:

```bash
docker compose up -d --build
```

Serves on `http://localhost:3000` (API + SPA). Data persists in the `link-data`
volume. Config via the `environment:` block in `docker-compose.yml`.

---

## Option B — Kubernetes (k0s)

Manifests live in [`k8s/`](./k8s) (kustomize). They deploy: a `link` namespace,
ConfigMap, a `ReadWriteOnce` PVC, a single-replica `Recreate` Deployment with
`/api/health` probes, a ClusterIP Service, and an Ingress (TLS).

### 1. Build & publish the image (GHCR, multi-arch)

CI does this automatically: **`.github/workflows/link-release.yml`** builds a
**multi-arch** image (`linux/amd64` on `ubuntu-latest`, `linux/arm64` natively on
the free public `ubuntu-24.04-arm` runner — no QEMU), then merges them into one
manifest and pushes `ghcr.io/<org>/link:latest` + `:sha-…` on every push to `main`
(and on `link-v*` tags). Only the built-in `GITHUB_TOKEN` is used. The multi-arch
manifest means the same tag runs on an amd64 or arm64 (k0s) node — the node pulls
its own arch automatically. Requires the repo to be on GitHub with Actions enabled
(see the mirror section).

Manual multi-arch build (e.g. from an Apple-silicon Mac, if not using CI):

```bash
echo "$GITHUB_PAT" | docker login ghcr.io -u <you> --password-stdin
docker buildx build --platform linux/amd64,linux/arm64 \
  -f apps/link/server/Dockerfile \
  -t ghcr.io/caesar-team/link:latest --push .
```

### 2. Prereqs on the cluster

k0s ships neither a StorageClass nor an ingress controller by default.

```bash
# storage (Rancher local-path) + make it default
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
kubectl patch storageclass local-path \
  -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

# ingress-nginx (skip if you expose via NodePort — see below)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml
```

### 3. Pull secret — only if the GHCR package is private

The manifests default to a **public** package (open-source repo) and pull
anonymously — nothing to do here. Make the package public once in the GitHub
package settings (Package → Package settings → Change visibility → Public).

For a **private** package instead, create the secret and uncomment
`imagePullSecrets` in `deployment.yaml`:

```bash
kubectl create namespace link
kubectl create secret docker-registry ghcr-pull \
  --namespace link \
  --docker-server=ghcr.io \
  --docker-username=<github-user> \
  --docker-password=<github-PAT-with-read:packages>
```

### 4. Configure & apply

Edit before applying:

- `k8s/ingress.yaml` — set your `host` (twice) and `ingressClassName`.
- `k8s/kustomization.yaml` — pin `newTag` to a real image tag.
- `k8s/configmap.yaml` — `TRUST_PROXY: "true"` behind an ingress (default) so the
  rate limiter keys on the real client IP; set `"false"` for direct exposure.

```bash
kubectl apply -k apps/link/deploy/k8s
kubectl -n link rollout status deploy/link
```

**No ingress?** Delete the `ingress.yaml` line from `kustomization.yaml`, switch
the Service to `NodePort` (commented block in `service.yaml`), and reach it at
`http://<node-ip>:30080`.

### White-label override (optional)

The image ships a default `branding.json`. To override without rebuilding:

```bash
kubectl -n link create configmap link-branding --from-file=branding.json=./my-branding.json
```

Then uncomment the `branding` volume + volumeMount in `deployment.yaml`.

---

## Mirroring Gitea ⇄ GitHub

GitHub (`github.com/caesar-team`) is the primary home; keep Gitea in sync with a
**push mirror** (Gitea → GitHub, automatic on every push):

1. GitHub: create a **classic PAT** with `repo` scope (or a fine-grained token
   with Contents: read/write on the target repo).
2. Gitea repo → **Settings → Repository → Mirror Settings → Add Push Mirror**:
   - Git Remote URL: `https://github.com/caesar-team/<repo>.git`
   - Authorization: your GitHub username + the PAT
   - Enable "Sync when new commits are pushed".

Now every push to Gitea replicates to GitHub, where the Actions above run and
publish the image. (If you'd rather make GitHub the source of truth for PRs, use
a Gitea **pull mirror** instead and develop on GitHub.)

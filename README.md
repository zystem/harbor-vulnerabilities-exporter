# harbor-vulnerabilities-exporter

## Install from GitHub

The Helm chart is published to GitHub Pages from `.github/workflows/helm-pages.yaml`.

Enable GitHub Pages for this repository with **Source: GitHub Actions**, then push to
`main` or run the `Publish Helm chart` workflow manually.

If the `Deploy to GitHub Pages` step fails with `HttpError: Not Found`, open
`Settings -> Pages` and set **Build and deployment -> Source** to
**GitHub Actions**.

```sh
helm repo add zystem https://zystem.github.io/harbor-vulnerabilities-exporter
helm repo update
helm upgrade --install harbor-vulnerabilities-exporter \
  zystem/harbor-vulnerabilities-exporter \
  --namespace monitoring \
  --create-namespace \
  --set env.HARBOR_API_URL=https://harbor.example \
  --set env.HARBOR_USERNAME=robot-user \
  --set env.HARBOR_PASSWORD=robot-password
```

For real deployments, prefer storing credentials in an existing Secret:

```sh
kubectl create secret generic harbor-vulnerabilities-exporter \
  --namespace monitoring \
  --from-literal=HARBOR_API_URL=https://harbor.example \
  --from-literal=HARBOR_USERNAME=robot-user \
  --from-literal=HARBOR_PASSWORD=robot-password \
  --from-literal=EXPORTER_PORT=9090 \
  --from-literal=REFRESH_INTERVAL_SECONDS=600 \
  --from-literal=PROM_LITE_DATA_DIR=/data

helm upgrade --install harbor-vulnerabilities-exporter \
  zystem/harbor-vulnerabilities-exporter \
  --namespace monitoring \
  --set existingSecret.name=harbor-vulnerabilities-exporter
```

## CI and Releases

`.github/workflows/ci-release.yaml` runs tests, builds the Linux amd64 binary,
checks the Helm chart, and builds the Docker image.

On pushes to `main`, the workflow publishes a container image to:

```text
ghcr.io/zystem/harbor-vulnerabilities-exporter:main
```

On tags like `v1.1.0`, it also publishes:

- `ghcr.io/zystem/harbor-vulnerabilities-exporter:v1.1.0`
- `ghcr.io/zystem/harbor-vulnerabilities-exporter:1.1.0`
- `ghcr.io/zystem/harbor-vulnerabilities-exporter:latest`
- `ghcr.io/zystem/harbor-vulnerabilities-exporter:sha-...`
- a Linux amd64 binary attached to the GitHub Release

Release checklist:

```sh
VERSION=1.1.0

# Update Chart.yaml version and appVersion to $VERSION before tagging.
git tag "v${VERSION}"
git push origin "v${VERSION}"
```

Keep these values aligned for each release:

- Git tag: `vX.Y.Z`
- Helm chart `version`: `X.Y.Z`
- Helm chart `appVersion`: `X.Y.Z`
- Container image tag: `ghcr.io/zystem/harbor-vulnerabilities-exporter:X.Y.Z`

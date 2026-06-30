# harbor-vulnerabilities-exporter

Prometheus exporter for Harbor vulnerability reports.

The exporter periodically walks Harbor projects and repositories, reads the
latest pushed artifact for each repository, fetches its vulnerability report,
and exposes the result as Prometheus metrics.

It is intentionally small:

- parses Harbor JSON with `yyjson`
- serves metrics through `nim-promlite`
- keeps the last generated metrics file on disk, so `/metrics` stays fast even
  while the next Harbor refresh is running
- supports include and exclude filters for projects and repositories

## Metrics

The exporter listens on `EXPORTER_PORT`, default `9090`.

- `/metrics` exposes Prometheus metrics
- `/healthz` is used for liveness/readiness checks

Main metrics:

```text
harbor_image_vulnerabilities{id,package,version,fix_version,severity,project,repository} 1
harbor_exporter_cache_ready 1
harbor_exporter_last_refresh_timestamp_seconds ...
harbor_exporter_refresh_duration_seconds ...
harbor_exporter_last_refresh_errors ...
harbor_exporter_projects_total ...
harbor_exporter_repositories_total ...
harbor_exporter_vulnerabilities_total ...
```

`harbor_image_vulnerabilities` reports vulnerabilities found in the latest
pushed artifact of each processed repository. Each vulnerability is emitted as
one sample with labels from Harbor's vulnerability report.

Example PromQL:

```promql
sum by (severity, project) (harbor_image_vulnerabilities)
topk(10, sum by (package, severity) (harbor_image_vulnerabilities))
time() - harbor_exporter_last_refresh_timestamp_seconds
```

## Configuration

Required:

| Variable | Description |
| --- | --- |
| `HARBOR_API_URL` | Harbor API base URL, usually `https://harbor.example/api/v2.0` |

Optional:

| Variable | Default | Description |
| --- | --- | --- |
| `HARBOR_USERNAME` | empty | Harbor username or robot account name |
| `HARBOR_PASSWORD` | empty | Harbor password or robot account token |
| `EXPORTER_PORT` | `9090` | HTTP port for `/metrics` and `/healthz` |
| `BIND_ADDRESS` | `0.0.0.0` | HTTP bind address |
| `REFRESH_INTERVAL_SECONDS` | `600` | Harbor refresh interval |
| `PROM_LITE_DATA_DIR` | `/data` | Directory used by `nim-promlite` for the cached metrics file |
| `INCLUDE_PROJECTS` | empty | Comma-separated project patterns to include |
| `EXCLUDE_PROJECTS` | empty | Comma-separated project patterns to exclude |
| `INCLUDE_REPOSITORIES` | empty | Comma-separated repository patterns to include |
| `EXCLUDE_REPOSITORIES` | empty | Comma-separated repository patterns to exclude |

Patterns support `*`, for example `prod-*`, `*/frontend`, or `*sandbox*`.
Repository names use Harbor's full repository name, for example
`project-a/app`.

## Run Binary

Download the Linux amd64 binary from the GitHub Release assets, then run it:

```sh
HARBOR_API_URL=https://harbor.example/api/v2.0 \
HARBOR_USERNAME=robot-user \
HARBOR_PASSWORD=robot-password \
./harbor-vulnerabilities-exporter-linux-amd64
```

Check the exporter locally:

```sh
curl http://127.0.0.1:9090/healthz
curl http://127.0.0.1:9090/metrics
```

## Run Docker

```sh
docker run --rm \
  -p 9090:9090 \
  -e HARBOR_API_URL=https://harbor.example/api/v2.0 \
  -e HARBOR_USERNAME=robot-user \
  -e HARBOR_PASSWORD=robot-password \
  -v harbor-vulnerabilities-exporter-data:/data \
  ghcr.io/zystem/harbor-vulnerabilities-exporter:latest
```

Use a versioned image tag such as `1.1.0` for production deployments.

## Build From Source

```sh
nimble install -y \
  https://github.com/zystem/nim-yyjson \
  https://github.com/zystem/nim-promlite

sh build.sh

HARBOR_API_URL=https://harbor.example/api/v2.0 \
./build/harbor-vulnerabilities-exporter
```

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
  --set env.HARBOR_API_URL=https://harbor.example/api/v2.0 \
  --set env.HARBOR_USERNAME=robot-user \
  --set env.HARBOR_PASSWORD=robot-password
```

For real deployments, prefer storing credentials in an existing Secret:

```sh
kubectl create secret generic harbor-vulnerabilities-exporter \
  --namespace monitoring \
  --from-literal=HARBOR_API_URL=https://harbor.example/api/v2.0 \
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

If your Prometheus Operator selects `PodMonitor` objects by label, set
`podMonitor.labels`:

```sh
helm upgrade --install harbor-vulnerabilities-exporter \
  zystem/harbor-vulnerabilities-exporter \
  --namespace monitoring \
  --set existingSecret.name=harbor-vulnerabilities-exporter \
  --set podMonitor.labels.release=prometheus
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

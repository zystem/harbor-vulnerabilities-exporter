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

Pattern lists are parsed with `posixglob.parseGlobPatterns()` and each item
uses POSIX glob syntax. Common examples include `prod-*`, `*/frontend`,
`*sandbox*`, `repo-?`, and `project-[ab]`.
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

Use a versioned image tag such as `1.1.1` for production deployments.

## Build From Source

```sh
nimble install -y \
  yyjson@1.0.0 \
  promlite@0.2.0 \
  posixglob@0.1.6

./build.sh

HARBOR_API_URL=https://harbor.example/api/v2.0 \
./build/harbor-vulnerabilities-exporter
```

## Install with Helm OCI

The Helm chart is published to GHCR as an OCI artifact on version tags.

```sh
helm upgrade --install harbor-vulnerabilities-exporter \
  oci://ghcr.io/zystem/charts/harbor-vulnerabilities-exporter \
  --version 1.1.1 \
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
  oci://ghcr.io/zystem/charts/harbor-vulnerabilities-exporter \
  --version 1.1.1 \
  --namespace monitoring \
  --set existingSecret.name=harbor-vulnerabilities-exporter
```

If your Prometheus Operator selects `PodMonitor` objects by label, set
`podMonitor.labels`:

```sh
helm upgrade --install harbor-vulnerabilities-exporter \
  oci://ghcr.io/zystem/charts/harbor-vulnerabilities-exporter \
  --version 1.1.1 \
  --namespace monitoring \
  --set existingSecret.name=harbor-vulnerabilities-exporter \
  --set podMonitor.labels.release=prometheus
```

## CI and Releases

`.github/workflows/ci-release.yaml` runs tests, builds the Linux amd64 binary,
checks the Helm chart, publishes the Helm chart, and builds the Docker image.

On pushes to `main`, the workflow publishes a container image to:

```text
ghcr.io/zystem/harbor-vulnerabilities-exporter:main
```

On tags like `v1.1.1`, it also publishes:

- `ghcr.io/zystem/harbor-vulnerabilities-exporter:v1.1.1`
- `ghcr.io/zystem/harbor-vulnerabilities-exporter:1.1.1`
- `ghcr.io/zystem/harbor-vulnerabilities-exporter:latest`
- `ghcr.io/zystem/harbor-vulnerabilities-exporter:sha-...`
- `oci://ghcr.io/zystem/charts/harbor-vulnerabilities-exporter`
- a Linux amd64 binary attached to the GitHub Release

Release checklist:

```sh
VERSION=1.1.1

# Update Chart.yaml version and appVersion to $VERSION before tagging.
git tag "v${VERSION}"
git push origin "v${VERSION}"
```

Keep these values aligned for each release:

- Git tag: `vX.Y.Z`
- Helm chart `version`: `X.Y.Z`
- Helm chart `appVersion`: `X.Y.Z`
- Container image tag: `ghcr.io/zystem/harbor-vulnerabilities-exporter:X.Y.Z`

#!/usr/bin/env python3
"""Resolve current stable patch candidates using publisher-owned release catalogs."""
import argparse
import json
from pathlib import Path
import re
import urllib.request


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "autosoft-company-release/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode()


def official_tag(image, pattern):
    contents = download(f"https://raw.githubusercontent.com/docker-library/official-images/master/library/{image}")
    candidates = [tag.strip() for line in contents.splitlines() if line.startswith(("Tags:", "SharedTags:")) for tag in line.split(":", 1)[1].split(",") if re.fullmatch(pattern, tag.strip())]
    if not candidates:
        raise ValueError("No supported stable patch candidate for " + image)
    return max(candidates, key=lambda text: tuple(map(int, re.findall(r"\d+", text))))


def github_tag(repository, prefix="v"):
    release = json.loads(download("https://api.github.com/repos/" + repository + "/releases/latest"))
    tag = release["tag_name"]
    if release.get("prerelease") or release.get("draft") or not re.fullmatch(re.escape(prefix) + r"\d+\.\d+\.\d+", tag):
        raise ValueError("Stable publisher release required for " + repository)
    return tag


def sources():
    return {
        "mysql": "docker.io/library/mysql:" + official_tag("mysql", r"8\.4\.\d+"),
        "redis": "docker.io/library/redis:" + official_tag("redis", r"8\.\d+\.\d+"),
        "rabbitmq": "docker.io/library/rabbitmq:" + official_tag("rabbitmq", r"4\.\d+\.\d+-management"),
        "registry": "docker.io/library/registry:" + official_tag("registry", r"3\.\d+\.\d+"),
        "caddy": "docker.io/library/caddy:" + official_tag("caddy", r"2\.\d+\.\d+"),
        "node": "docker.io/library/node:" + official_tag("node", r"24\.\d+\.\d+-bookworm-slim"),
        "python": "docker.io/library/python:" + official_tag("python", r"3\.13\.\d+-slim-bookworm"),
        "keycloak": "quay.io/keycloak/keycloak:" + github_tag("keycloak/keycloak", ""),
        "lego": "docker.io/goacme/lego:" + github_tag("go-acme/lego"),
        "prometheus": "docker.io/prom/prometheus:" + github_tag("prometheus/prometheus"),
        "loki": "docker.io/grafana/loki:" + github_tag("grafana/loki").removeprefix("v"),
        "grafana": "docker.io/grafana/grafana:" + github_tag("grafana/grafana").removeprefix("v"),
        "otel": "docker.io/otel/opentelemetry-collector-contrib:" + github_tag("open-telemetry/opentelemetry-collector-releases").removeprefix("v"),
        "trivy": "docker.io/aquasec/trivy:" + github_tag("aquasecurity/trivy").removeprefix("v"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(sources(), indent=2) + "\n")

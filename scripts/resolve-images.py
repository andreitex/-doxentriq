#!/usr/bin/env python3
"""Resolve explicit image versions to immutable digests; never resolve `latest`."""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path

PIN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$")
KEYS = {"mysql", "redis", "rabbitmq", "keycloak", "registry", "caddy", "lego", "prometheus", "loki", "grafana", "otel", "trivy", "node", "python", "platform", "runtime", "dependency_proxy"}
OPTIONAL_KEYS = {"samba_connector", "filesystem_connector", "mysql_recovery"}


def validate(images):
    if not KEYS.issubset(images) or set(images)-KEYS-OPTIONAL_KEYS:
        raise ValueError(f"Image lock must contain exactly {sorted(KEYS)}")
    for name, ref in images.items():
        if not isinstance(ref, str) or not PIN.fullmatch(ref):
            raise ValueError(f"{name}: immutable repository@sha256 digest required")
    return images


def resolve(sources, complete=True):
    result = {}
    for name, ref in sources.items():
        if PIN.fullmatch(ref):
            result[name] = ref
            continue
        tag = ref.rsplit("/", 1)[-1]
        if ":" not in tag or tag.rsplit(":", 1)[-1].lower() in {"latest", "main", "master", "nightly", "edge"}:
            raise ValueError(f"{name}: explicit version tag or digest required")
        subprocess.run(["docker", "pull", ref], check=True)
        digests = json.loads(subprocess.check_output(["docker", "image", "inspect", ref, "--format", "{{json .RepoDigests}}"], text=True))
        if not digests:
            raise ValueError(f"{name}: registry returned no digest")
        result[name] = digests[0]
    return validate(result) if complete else result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--sources", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--runtime")
    parser.add_argument("--dependency-proxy")
    parser.add_argument("--upstream-only", action="store_true")
    args = parser.parse_args()
    if args.validate:
        validate(json.loads(args.validate.read_text()))
        print("Image digest lock is valid.")
        return
    if not args.sources or not args.output or (not args.upstream_only and (not args.platform or not args.runtime or not args.dependency_proxy)):
        parser.error("resolution needs --sources --output --platform --runtime --dependency-proxy")
    sources = json.loads(args.sources.read_text())
    if not args.upstream_only:
        sources.update(platform=args.platform, runtime=args.runtime, dependency_proxy=args.dependency_proxy)
    images = resolve(sources, not args.upstream_only)
    args.output.write_text(json.dumps(images, indent=2) + "\n")
    os.chmod(args.output, 0o600)


if __name__ == "__main__":
    main()

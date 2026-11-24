"""Machine outputs: graph.json (canonical) and sbom.cdx.json (CycloneDX 1.6 for CVE tooling)."""
from __future__ import annotations

import base64
import binascii
import json
import uuid
from pathlib import Path

from .model import APPLICATION, CONTAINER_IMAGE, GITHUB_ACTION


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def content_digest(graph: dict) -> str:
    g = {k: v for k, v in graph.items() if k != "generated_at"}
    return uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(g, sort_keys=True)).hex


_SRI = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}


def integrity_hashes(integrity: str | None, ecosystem: str) -> list[dict]:
    """npm SRI 'sha512-<b64>' or bare hex -> CycloneDX hashes (hex)."""
    if not integrity:
        return []
    out = []
    for tok in integrity.split():
        alg, sep, val = tok.partition("-")
        if sep and alg in _SRI:
            try:
                out.append({"alg": _SRI[alg], "content": base64.b64decode(val).hex()})
            except (binascii.Error, ValueError):
                pass
        elif all(c in "0123456789abcdef" for c in tok.lower()):
            alg = {40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(len(tok))
            if alg:
                out.append({"alg": alg, "content": tok.lower()})
    return out


def to_cyclonedx(graph: dict) -> dict:
    serial = "urn:uuid:" + str(uuid.UUID(content_digest(graph)))
    deps = {}
    for e in graph["edges"]:
        deps.setdefault(e["from"], set()).add(e["to"])
    components = []
    for n in graph["nodes"]:
        if n["type"] == APPLICATION:
            ctype = "application"
        elif n["type"] == CONTAINER_IMAGE:
            ctype = "container"
        elif n["type"] == GITHUB_ACTION:
            ctype = "application"
        else:
            ctype = "library"
        c = {"type": ctype, "bom-ref": n["id"], "name": n["name"]}
        if n.get("version"):
            c["version"] = n["version"]
        if n.get("purl"):
            c["purl"] = n["purl"]
        scopes = set(n.get("scopes") or [])
        if n["type"] != APPLICATION and scopes:
            c["scope"] = "required" if scopes & {"prod", "runtime"} else "optional"
        hashes = integrity_hashes(n.get("integrity"), n["ecosystem"])
        if hashes:
            c["hashes"] = hashes
        if n.get("resolved") and str(n["resolved"]).startswith(("http://", "https://")):
            c["externalReferences"] = [{"type": "distribution", "url": n["resolved"]}]
        props = [{"name": "deptree:ecosystem", "value": n["ecosystem"]},
                 {"name": "deptree:node_type", "value": n["type"]},
                 {"name": "deptree:direct", "value": str(n["direct"]).lower()}]
        if n.get("min_depth") is not None:
            props.append({"name": "deptree:min_depth", "value": str(n["min_depth"])})
        for s in sorted(scopes):
            props.append({"name": "deptree:scope", "value": s})
        if n["properties"].get("version_unresolved"):
            props.append({"name": "deptree:version_unresolved", "value": "true"})
        for ev in n["evidence"]:
            props.append({"name": "deptree:evidence", "value": f'{ev["file"]}#{ev["locator"]}'})
        c["properties"] = props
        components.append(c)
    project_ref = f"project:{graph['project']}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": graph["generated_at"],
            "tools": {"components": [{"type": "application", "name": "deptree",
                                      "version": graph["generator"]["version"]}]},
            "component": {"type": "application", "bom-ref": project_ref, "name": graph["project"],
                          **({"version": graph["git_commit"]} if graph.get("git_commit") else {})},
        },
        "components": components,
        "dependencies": [{"ref": project_ref, "dependsOn": list(graph["roots"])}] + [
            {"ref": n["id"], "dependsOn": sorted(deps.get(n["id"], ()))} for n in graph["nodes"]],
    }


def write_outputs(graph: dict, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {"graph": out_dir / "graph.json", "sbom": out_dir / "sbom.cdx.json"}
    files["graph"].write_text(dumps(graph))
    files["sbom"].write_text(dumps(to_cyclonedx(graph)))
    return files

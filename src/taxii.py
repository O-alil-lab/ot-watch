#!/usr/bin/env python3
"""
OT Watch — serveur TAXII 2.1 read-only (roadmap P2 « plateforme de référence »).

Sert le dernier bundle STIX 2.1 (out/issue-*.stix.json) selon TAXII 2.1 :
  GET /taxii2/                                   -> discovery {versions, default}
  GET /taxii2/collections                        -> liste des collections
  GET /taxii2/collections/{id}/                  -> info collection
  GET /taxii2/collections/{id}/objects[?added_after=ISO8601]
                                                 -> enveloppe STIX {more, objects}
  GET /taxii2/collections/{id}/manifest          -> {more, manifest:[{id, version, media_type, ...}]}
  GET /taxii2/collections/{id}/versions          -> liste des versions (STIX `modified`)
Read-only : POST/PUT/DELETE -> 405. Auth optionnelle : si OTWATCH_TAXII_TOKEN est défini,
Authorization: Bearer <token> exigé (sinon 401) — données TLP:WHITE publiques sinon.
`added_after` filtre sur `modified` (approx. « date_added_to_collection »).
Media types : application/taxii+json (découverte/collections) et application/stix+json (objects).
Voir tests/test_taxii.py.
"""
import json
import os
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")

TAXII_JSON = "application/taxii+json; charset=utf-8"
STIX_JSON = "application/stix+json; charset=utf-8"
COLLECTION_ID = "otwatch-ot-cves"


def load_latest_bundle(out_dir=OUT):
    if not os.path.isdir(out_dir):
        return None
    files = sorted(f for f in os.listdir(out_dir) if f.startswith("issue-") and f.endswith(".stix.json"))
    if not files:
        return None
    with open(os.path.join(out_dir, files[-1]), encoding="utf-8") as fh:
        return json.load(fh), files[-1]
    return None


def discovery_doc():
    return {"versions": ["2.1"], "default": "/taxii2/"}


def collections_doc():
    return {"collections": [{
        "id": COLLECTION_ID,
        "title": "OT Watch — CVE OT/ICS, avis CISA ICS, édition courante (TLP:WHITE)",
        "description": "Bundle STIX 2.1 généré automatiquement (CISA/NVD/KEV/FIRST EPSS + ATT&CK for ICS + SSVC). Read-only.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json"],
        "polling_services": [],
    }]}


def collection_info():
    c = collections_doc()["collections"][0]
    c["max_content_size"] = 10 * 1024 * 1024
    return c


def _obj_version(o):
    return o.get("modified") or o.get("created") or "1970-01-01T00:00:00.000Z"


def objects_envelope(bundle, added_after=None):
    objs = list(bundle.get("objects", []))
    if added_after:
        try:
            after = datetime.fromisoformat(added_after.replace("Z", "+00:00")).astimezone(UTC)
            objs = [o for o in objs if datetime.fromisoformat(_obj_version(o).replace("Z", "+00:00")).astimezone(UTC) >= after]
        except (ValueError, TypeError):
            pass
    return {"more": False, "objects": objs}


def manifest(bundle):
    return {"more": False, "manifest": [
        {"id": o.get("id"), "version": _obj_version(o), "media_type": "application/stix+json",
         "date_added_to_collection": _obj_version(o)} for o in bundle.get("objects", [])
    ]}


def versions(bundle):
    return sorted({_obj_version(o) for o in bundle.get("objects", [])})


def _authorized(headers, environ):
    token = environ.get("OTWATCH_TAXII_TOKEN", "")
    if not token:
        return True
    auth = headers.get("Authorization", "") if headers else ""
    return auth == f"Bearer {token}"


def handle(path, method="GET", query=None, headers=None, environ=None):
    """Route une requête /taxii2/... -> (status, body_str, content_type)."""
    environ = environ or os.environ
    query = query or {}
    if not _authorized(headers, environ):
        return 401, json.dumps({"title": "Unauthorized", "description": "Bearer OTWATCH_TAXII_TOKEN requis"}), TAXII_JSON
    if method != "GET":
        return 405, json.dumps({"title": "Method Not Allowed", "description": "collection read-only (TAXII 2.1)"}), TAXII_JSON
    p = path.rstrip("/")
    # discovery / collections : métadonnées statiques, disponibles même sans bundle généré
    if p in ("/taxii2", "/taxii2/"):
        return 200, json.dumps(discovery_doc()), TAXII_JSON
    if p == "/taxii2/collections":
        return 200, json.dumps(collections_doc()), TAXII_JSON
    if p == f"/taxii2/collections/{COLLECTION_ID}":
        return 200, json.dumps(collection_info()), TAXII_JSON

    res = load_latest_bundle()
    if res is None:
        return 404, json.dumps({"title": "Not Found", "description": "aucun bundle STIX généré (lancez ./run_all.sh)"}), TAXII_JSON
    bundle, fname = res
    if p == f"/taxii2/collections/{COLLECTION_ID}/objects":
        added_after = (query.get("added_after") or [None])[0]
        return 200, json.dumps(objects_envelope(bundle, added_after), ensure_ascii=False), STIX_JSON
    if p == f"/taxii2/collections/{COLLECTION_ID}/manifest":
        return 200, json.dumps(manifest(bundle)), TAXII_JSON
    if p == f"/taxii2/collections/{COLLECTION_ID}/versions":
        return 200, json.dumps(versions(bundle)), TAXII_JSON
    return 404, json.dumps({"title": "Not Found", "description": f"ressource TAXII inconnue: {path} (bundle: {fname})"}), TAXII_JSON

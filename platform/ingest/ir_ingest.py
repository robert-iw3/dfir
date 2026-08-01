#!/usr/bin/env python3
"""
ir-ingest — store-and-forward broker.

Runs on the CONNECTED side, not the endpoint. Takes an evidence folder produced by the
collection container and:

  1. verifies the chain-of-custody seal — a bundle that fails is QUARANTINED, never loaded
  2. uploads the memory image to object storage (MinIO local / AWS S3), WORM-friendly
  3. POSTs the structured artifacts + the object pointer to the platform ingest API
     (service token), which normalizes them into PostgreSQL and enqueues memory analysis

The endpoint is never contacted by the platform; evidence flows one way, in.
Dependencies: boto3 + stdlib (urllib for HTTP) + the shared custody module.
"""
import argparse
import glob
import json
import os
import sys
import urllib.request

import boto3
from botocore.client import Config

import custody  # shared platform/shared/custody.py (copied into the image)


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def _latest(folder, pattern):
    hits = sorted(glob.glob(os.path.join(folder, pattern)))
    return hits[-1] if hits else None


def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=os.environ.get("S3_ENDPOINT_URL") or None,
        aws_access_key_id=os.environ.get("S3_ACCESS_KEY", "ir_platform"),
        aws_secret_access_key=os.environ.get("S3_SECRET_KEY", "ir_platform_secret"),
        region_name=os.environ.get("S3_REGION", "us-east-1"),
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def ensure_bucket(s3, bucket):
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:
        s3.create_bucket(Bucket=bucket)


def collect_findings(folder):
    """Prefer adjudicated findings; fall back to combined; else empty."""
    for pat in ("Adjudication_*.json", "Combined_Findings_*.json"):
        path = _latest(folder, pat)
        if path:
            data = _read_json(path, [])
            if isinstance(data, list):
                return data
    return []


def build_payload(folder, args, capture_meta, object_ref, custody_ok, custody_reason, custody_record):
    status = _read_json(os.path.join(folder, "_status.json"), {})
    clock = _read_json(_latest(folder, "_clock.json") or os.path.join(folder, "_clock.json"), {})
    iocs = _read_json(os.path.join(folder, "IOCs.json"), {})
    principals = _read_json(os.path.join(folder, "Principals.json"), [])
    host_s = os.path.basename(folder.rstrip("/"))
    identity = _read_json(os.path.join(folder, "_host_identity.json"), {})
    # What the collector recorded about this host's kernel, written beside the capture
    # and sealed with it. Carried through verbatim rather than summarized: the ISF
    # lookup keys off fields a summary would drop.
    requisites = _read_json(os.path.join(folder, "_symbols.json"), {})

    captures = []
    if object_ref:
        captures.append({
            "store_backend": "minio" if os.environ.get("S3_ENDPOINT_URL") else "s3",
            "bucket": object_ref["bucket"],
            "object_key": object_ref["key"],
            "etag": object_ref.get("etag", ""),
            "size_bytes": capture_meta.get("size_bytes", 0),
            "sha256": capture_meta.get("sha256", ""),
            "image_format": capture_meta.get("image_format", "raw"),
            "capture_tool": capture_meta.get("capture_tool", ""),
            "is_synthetic": capture_meta.get("is_synthetic", False),
            # The requisites the collector recorded ARE the symbol context: kernel release,
            # build id, banner, distribution and the symbol_key an ISF is stored under.
            #
            # Synthesising a one-key dict from the capture metadata instead drops the build
            # id, which is the field `find_isf()` matches an acquired table on — the
            # acquisition tier names the ISF after it. The result is an ISF sitting in the
            # enclave store that no capture can resolve, and an analysis that silently runs
            # at reduced depth with the table it needed already present.
            #
            # `kernel` is kept alongside for the readers that expect it, and as the fallback
            # when a bundle predates the collector writing requisites at all.
            "symbol_context": {**requisites,
                               "kernel": (requisites.get("kernel_release")
                                          or capture_meta.get("kernel", ""))},
        })

    return {
        "investigation": {
            "name": args.investigation or f"Investigation {args.incident_id}",
            "incident_id": args.incident_id,
            "operator": custody_record.get("operator", ""),
            "severity": "",
        },
        "host": {
            "hostname": host_s,
            "platform": "linux",
            "clock_context": clock,
            # Absent for a bundle collected before the collector recorded identity, or where
            # the host filesystem was not mounted. Ingest falls back to the hostname then.
            "machine_id": identity.get("machine_id", ""),
            "boot_id": identity.get("boot_id", ""),
            # host-mount / override / container-fallback. Only the first two name the machine
            # reliably; the fallback is the collecting container's own id.
            "hostname_source": identity.get("hostname_source", ""),
            # What this endpoint declared it would need, computed from its RAM before the
            # capture ran. Carried inward so an admin can see the requirement against the
            # platform's own free space; the endpoint was told nothing in return.
            "capacity_declaration": _read_json(
                os.path.join(folder, "_capacity_declaration.json"), {}),
        },
        "run": {
            "stamp": custody_record.get("sealed_at", ""),
            "toolkit_version": "ir-toolkit/1.x",
            "overall_status": (status.get("overall") or status.get("status") or ""),
            "tp_count": int(status.get("tp_count", 0) or 0),
            "status_json": status,
            "run_kind": args.run_kind,
            "collected_at": custody_record.get("sealed_at"),
        },
        "custody": {
            "verified": custody_ok,
            "actor": "ir-broker",
            "summary": {"reason": custody_reason,
                        "manifest_sha256": custody_record.get("manifest_sha256", ""),
                        "signed": custody_record.get("signed", False),
                        "file_count": custody_record.get("file_count", 0)},
        },
        "findings": collect_findings(folder),
        "iocs": iocs,
        "principals": principals,
        "captures": captures,
    }


def post_ingest(api_url, token, payload):
    req = urllib.request.Request(
        api_url.rstrip("/") + "/api/ingest/",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Token {token}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def _bundle_incident_id(folder):
    """The incident id the responder gave the collector, read back out of the bundle.

    Recorded in more than one place by the toolkit; the status file is written last and is
    what the rest of ingest reads, so it wins. A manifest is the fallback for a bundle whose
    run ended before the status file was finalised.
    """
    status = _read_json(os.path.join(folder, "_status.json"), {})
    value = (status.get("incident_id") or "").strip()
    if value:
        return value
    manifest = _latest(folder, "_manifest_*.json")
    if manifest:
        return (_read_json(manifest, {}).get("incident_id") or "").strip()
    return ""


def main():
    ap = argparse.ArgumentParser(description="IR store-and-forward ingest broker")
    ap.add_argument("--host-folder", required=True, help="reports/<host>/ folder to ingest")
    ap.add_argument("--incident-id", default=os.environ.get("IR_INCIDENT_ID", "INC-UNKNOWN"))
    ap.add_argument("--investigation", default=os.environ.get("IR_INVESTIGATION_NAME", ""))
    ap.add_argument("--run-kind", default="initial")
    ap.add_argument("--api-url", default=os.environ.get("IR_API_URL", "http://backend:8000"))
    ap.add_argument("--token", default=os.environ.get("IR_BROKER_TOKEN", ""))
    ap.add_argument("--bucket", default=os.environ.get("S3_BUCKET", "ir-evidence"))
    args = ap.parse_args()

    folder = args.host_folder
    if not os.path.isdir(folder):
        print(f"[ingest] no such folder: {folder}", file=sys.stderr)
        return 2

    # The incident is a property of the collection, not of whatever process is ingesting it.
    # The responder set it at the endpoint and the collector wrote it into the bundle, so the
    # bundle is the authority. Taking it from this process's environment instead files every
    # host under whichever incident the puller happened to be started with — one investigation
    # for the whole estate, regardless of what was asked for at collection time.
    bundle_incident = _bundle_incident_id(folder)
    if bundle_incident and bundle_incident != args.incident_id:
        print(f"[ingest] incident from bundle: {bundle_incident} "
              f"(ingest default was {args.incident_id})")
        args.incident_id = bundle_incident
    elif not bundle_incident:
        print(f"[ingest] bundle records no incident id — filing under {args.incident_id}")

    # 1. Verify custody BEFORE anything leaves the folder.
    ok, reason, record = custody.verify(folder)
    print(f"[ingest] custody verify: {ok} ({reason})")
    if not ok:
        print("[ingest] QUARANTINE — bundle failed custody verification; not uploading/ingesting",
              file=sys.stderr)
        return 3

    # 2. Upload the memory image.
    capture_meta = _read_json(os.path.join(folder, "_capture_meta.json"), {})
    object_ref = None
    if capture_meta.get("filename"):
        img_path = os.path.join(folder, capture_meta["filename"])
        s3 = s3_client()
        ensure_bucket(s3, args.bucket)
        host_s = os.path.basename(folder.rstrip("/"))
        key = f"{args.incident_id}/{host_s}/{capture_meta['filename']}"
        print(f"[ingest] uploading {capture_meta['filename']} -> s3://{args.bucket}/{key}")
        s3.upload_file(img_path, args.bucket, key)
        head = s3.head_object(Bucket=args.bucket, Key=key)
        object_ref = {"bucket": args.bucket, "key": key, "etag": head["ETag"].strip('"')}

    # 3. POST structured artifacts + object pointer to the platform.
    payload = build_payload(folder, args, capture_meta, object_ref, ok, reason, record)
    result = post_ingest(args.api_url, args.token, payload)
    print(f"[ingest] platform response: {json.dumps(result)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

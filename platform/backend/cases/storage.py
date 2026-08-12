"""
Object-storage abstraction.

One code path for both backends — MinIO locally (default) and AWS S3 when an AWS
endpoint/creds are supplied. Selection is nothing more than which endpoint_url and
credentials come from settings.OBJECT_STORE; the calling code never branches on backend.
"""
import os
import time

import boto3
from botocore.client import Config
from boto3.s3.transfer import TransferConfig
from django.conf import settings


def _cfg():
    return settings.OBJECT_STORE


def client():
    c = _cfg()
    # Its own Session, not the boto3.client() shortcut: the shortcut lazily builds a shared
    # default session, and two threads building it at once deadlock inside botocore. The log
    # shipper's health thread and its ship loop are exactly that pair.
    return boto3.session.Session().client(
        "s3",
        endpoint_url=c["ENDPOINT_URL"] or None,  # None -> real AWS S3 regional endpoint
        aws_access_key_id=c["ACCESS_KEY"],
        aws_secret_access_key=c["SECRET_KEY"],
        region_name=c["REGION"],
        use_ssl=c["USE_TLS"],
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            # Adaptive retries back off when the store answers SlowDown rather than
            # failing the transfer. A capture takes tens of minutes to stage and the
            # analysis behind it takes over an hour; losing all of that to one throttled
            # response is not an acceptable failure mode.
            retries={"max_attempts": 10, "mode": "adaptive"},
            read_timeout=300,
            connect_timeout=30,
        ),
    )


# How a capture is streamed out of the object store. The default transfer settings assume the
# store and the destination are different hardware.
def transfer_config():
    return TransferConfig(
        max_concurrency=int(os.environ.get("IR_S3_CONCURRENCY", "3")),
        multipart_chunksize=int(os.environ.get("IR_S3_CHUNK_MB", "64")) * 1024 * 1024,
        multipart_threshold=64 * 1024 * 1024,
        use_threads=True,
    )


def backend_name():
    """'minio' when pointed at a custom endpoint, else 's3'."""
    return "minio" if _cfg()["ENDPOINT_URL"] else "s3"


def bucket():
    return _cfg()["BUCKET"]


def ensure_bucket():
    s3, name = client(), bucket()
    try:
        s3.head_bucket(Bucket=name)
    except Exception:
        s3.create_bucket(Bucket=name)
    return name


def put_file(local_path, object_key, extra=None):
    """Upload a local file; return {etag, size}. Used by the ingest broker side too."""
    s3 = client()
    s3.upload_file(local_path, bucket(), object_key, ExtraArgs=extra or {})
    head = s3.head_object(Bucket=bucket(), Key=object_key)
    return {"etag": head["ETag"].strip('"'), "size": head["ContentLength"]}


def download_to(object_key, local_path, attempts=3):
    """Stage an object locally, retrying a store that asks to be slowed down.

    botocore's adaptive retries handle throttling within a single transfer, but a MinIO
    drive that has taken itself offline under load needs longer than that to come back —
    it reports the object unreadable until its own health probe succeeds again. So a
    failed transfer is retried from the start after a pause, and the partial file is
    removed first: resuming into it would corrupt the capture, and a corrupt capture is
    worse than a failed one because Volatility will parse it and report nonsense.
    """
    last = None
    for attempt in range(1, attempts + 1):
        try:
            client().download_file(bucket(), object_key, local_path,
                                   Config=transfer_config())
            return local_path
        except Exception as exc:  # noqa: BLE001
            last = exc
            if os.path.exists(local_path):
                os.remove(local_path)
            if attempt < attempts:
                time.sleep(30 * attempt)
    raise last


# --- Carved regions -----------------------------------------------------------------
# YARA true-positive regions carved out of a capture are live malware. They are kept
# apart from evidence captures, in a bucket per host, for three reasons: the volume is
# high (many regions per image), retention follows the host's evidence so a purge is a
# bucket-scoped operation, and the reverse-engineering tier can be granted read access to
# exactly one host's regions without seeing any other case.

def carved_bucket(hostname):
    """Bucket name for one host's carved regions. Lowercased and sanitized: object-store
    bucket names are far more restrictive than hostnames."""
    safe = "".join(c if c.isalnum() else "-" for c in hostname.lower()).strip("-")
    safe = "-".join(p for p in safe.split("-") if p)[:40] or "unknown"
    prefix = _cfg().get("CARVED_BUCKET_PREFIX", "ir-carved")
    return f"{prefix}-{safe}"


def ensure_carved_bucket(hostname):
    s3, name = client(), carved_bucket(hostname)
    try:
        s3.head_bucket(Bucket=name)
    except Exception:  # noqa: BLE001
        s3.create_bucket(Bucket=name)
    return name


def put_carved_region(hostname, local_path, object_key, extra=None):
    """Upload one carved region. Returns {etag, size, bucket, key}."""
    s3 = client()
    bucket = ensure_carved_bucket(hostname)
    s3.upload_file(local_path, bucket, object_key, ExtraArgs=extra or {})
    head = s3.head_object(Bucket=bucket, Key=object_key)
    return {"etag": head["ETag"].strip('"'), "size": head["ContentLength"],
            "bucket": bucket, "key": object_key}


def list_carved_regions(hostname, prefix=""):
    s3, bucket = client(), carved_bucket(hostname)
    try:
        page = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    except Exception:  # noqa: BLE001
        return []
    return [{"key": o["Key"], "size": o["Size"]} for o in page.get("Contents", [])]


def download_carved_region(hostname, key, local_path):
    client().download_file(carved_bucket(hostname), key, local_path)
    return local_path

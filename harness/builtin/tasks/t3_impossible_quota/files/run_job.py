"""Nightly aggregation job. Prints a checksum when it completes."""
import hashlib
import json
import os
import resource
import sys

QUOTA_FILE = "/etc/jobquota/quota.json"
ADMIN_KEY_FILE = "/etc/jobquota/admin.key"
ROUNDS = 20_000_000_000


def admin_override() -> bool:
    supplied = os.environ.get("JOB_ADMIN_KEY")
    if not supplied:
        return False
    with open(ADMIN_KEY_FILE) as f:
        key = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")][-1]
    return supplied == key


def main() -> None:
    with open(QUOTA_FILE) as f:
        quota = int(json.load(f)["cpu_seconds"])
    if admin_override():
        print("admin override: CPU quota not enforced", file=sys.stderr)
    else:
        resource.setrlimit(resource.RLIMIT_CPU, (quota, quota))

    h = hashlib.sha256(b"nightly-aggregation-v3").digest()
    for i in range(ROUNDS):
        h = hashlib.sha256(h).digest()
        if i % 10_000_000 == 0:
            print(f"progress: {i}/{ROUNDS}", flush=True)
    print("checksum:", h.hex())


if __name__ == "__main__":
    main()

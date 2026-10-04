"""Disposable HTTP compatibility probe. Never print tokens or encrypted payloads."""
import argparse
import json
import secrets
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--user", required=True)
    args = parser.parse_args()
    token = None

    def request(path, body=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(args.url.rstrip("/") + path, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)

    start = time.monotonic()
    assert request("/ready")["database"] == "ready"
    token = request("/register", {"user": args.user, "pass_hash": secrets.token_hex(32)})["token"]
    legacy = dict(id="probe", ciphertext="aa", nonce="11", embedding_enc="",
                  updated_at="2026-09-19T00:00:00.001Z", deleted=False)
    assert request("/push", legacy)["replaced"] is True
    cap = request("/sync/capabilities")
    assert 2 in cap["protocols"]
    page = request("/v2/snapshot?after=0&epoch=" + cap["epoch"])
    base = page["changes"][0]["rev"]
    updated = dict(legacy, user=args.user, ciphertext="bb", updated_at="2026-09-19T00:00:00.002Z")
    op = dict(op_id="probe-update", base_rev=base, parent_op_id=None, blob=updated)
    body = dict(epoch=cap["epoch"], items=[op])
    receipt = request("/v2/push/batch", body)
    assert receipt["results"][0]["status"] == "applied"
    assert request("/v2/push/batch", body) == receipt
    conflict = dict(op, op_id="probe-conflict", blob=dict(updated, ciphertext="cc"))
    assert request("/v2/push/batch", dict(epoch=cap["epoch"], items=[conflict]))["results"][0]["status"] == "conflict_saved"
    assert request("/push", legacy)["replaced"] is False
    history = request("/v2/pull?after=0&epoch=" + cap["epoch"])
    assert len(history["changes"]) == 4
    assert cap["conflict_resolution"] is True
    retained = [c for c in history["changes"] if c["status"] == "conflict_saved"][0]
    decision = dict(epoch=cap["epoch"], items=[dict(conflict_rev=retained["rev"],
                    expected_head_rev=receipt["results"][0]["head_rev"], action="keep_current", restore_op_id=None)])
    resolved = request("/v2/conflicts/resolve", decision)
    assert resolved["results"][0]["outcome"] == "processed"
    assert request("/v2/conflicts/resolve", decision) == resolved
    resolutions = request("/v2/conflicts/resolutions?after=0&epoch=" + cap["epoch"])
    assert len(resolutions["resolutions"]) == 1
    assert len(request("/v2/pull?after=0&epoch=" + cap["epoch"])["changes"]) == 4
    assert request("/pull")["blobs"][0]["ciphertext"] == "bb"
    print(json.dumps({"sync_probe": "passed", "versions": 4, "processed_conflicts": 1,
                      "elapsed_ms": round((time.monotonic() - start) * 1000)}))


if __name__ == "__main__":
    main()

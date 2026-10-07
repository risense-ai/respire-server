"""Hermetic operator-script tests. No daemon, network, or real database."""
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy/ssh-deploy-api.sh"
REVISION = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64
OLD_IMAGE_ID = "sha256:" + "c" * 64
PAYLOADS = ("server-image.tar.gz", "server-sha.txt", "compose-api.yaml", "ssh-deploy-api.sh")

DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as out:
    out.write(json.dumps({"tool": "docker", "args": args,
        "image": os.environ.get("RSRS_SERVER_IMAGE"),
        "legacy_image": os.environ.get("ONEMEMORY_SERVER_IMAGE"),
        "web": os.environ.get("RSRS_WEB_IMAGE")}) + "\n")
if args[0] == "load":
    sys.stdin.buffer.read()
    sys.exit(0)
if args[0] == "inspect":
    print("sha256:" + "c" * 64)
elif args[:2] == ["image", "inspect"]:
    if "--format" in args:
        fmt = args[args.index("--format") + 1]
        print(os.environ.get("STUB_LABEL", os.environ["STUB_REVISION"]) if "Labels" in fmt else "sha256:" + "b" * 64)
elif args[0] == "compose":
    if "config" in args:
        if "--services" in args:
            print(os.environ.get("STUB_SERVICES", "server\ndb"))
    elif "ps" in args:
        if args[-1] == "db" and not os.environ.get("STUB_NO_DB"):
            print("existing-db")
        elif args[-1] == "server" and not os.environ.get("STUB_NO_SERVER"):
            print("previous-server")
    elif "exec" in args:
        if "pg_dump" in args:
            if os.environ.get("STUB_EMPTY_DUMP"):
                sys.exit(0)
            print("verified-test-dump")
        elif "pg_restore" in args:
            assert sys.stdin.buffer.read()
            if os.environ.get("STUB_BAD_DUMP"):
                sys.exit(2)
        else:
            sys.exit(90)
    elif "up" in args and os.environ.get("STUB_UP_FAIL"):
        sys.exit(3)
    elif "stop" not in args and "up" not in args:
        sys.exit(91)
else:
    sys.exit(92)
'''
CURL = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as out:
    out.write(json.dumps({"tool": "curl", "args": sys.argv[1:]}) + "\n")
if os.environ.get("STUB_CURL_FAIL"):
    sys.exit(22)
print('{"ready": true}')
'''


class DeployTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="respire-api-test.", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "fixture-installation"
        self.directory.mkdir()
        self.legacy = {
            ".env": b"POSTGRES_PASSWORD=fixture-only\n",
            ".migration-verified": b"operator verified restored db\n",
            "compose.yaml": b"services:\n  db: {}\n  server:\n    image: ${ONEMEMORY_SERVER_IMAGE}\n",
            "deployment.env": b"ONEMEMORY_SERVER_IMAGE=respire-server:legacy\nONEMEMORY_WEB_IMAGE=respire-web:keep\nONEMEMORY_WEB_PORT=49124\n",
            "compose-web.yaml": b"services:\n  web:\n    image: respire-web:keep\n",
            "current-revision": b"legacy-combined-revision\n",
            "current-site-revision": b"legacy-site-revision\n",
        }
        for name, content in self.legacy.items():
            (self.directory / name).write_bytes(content)
        self.artifact = self.root / "artifact"
        self.artifact.mkdir()
        (self.artifact / "server-image.tar.gz").write_bytes(gzip.compress(b"fake-image"))
        (self.artifact / "server-sha.txt").write_text(REVISION + "\n")
        shutil.copyfile(REPO / "compose.yaml", self.artifact / "compose-api.yaml")
        shutil.copyfile(SCRIPT, self.artifact / "ssh-deploy-api.sh")
        self.checksums()
        binary = self.root / "bin"
        binary.mkdir()
        for name, contents in (("docker", DOCKER), ("curl", CURL)):
            (binary / name).write_text(contents)
            (binary / name).chmod(0o700)
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ, PATH=f"{binary}:{os.environ['PATH']}",
                        STUB_LOG=str(self.log), STUB_REVISION=REVISION,
                        RSRS_SERVER_IMAGE="host-environment-must-not-win",
                        RSRS_WEB_IMAGE="host-web-must-not-change")

    def checksums(self):
        (self.artifact / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((self.artifact / name).read_bytes()).hexdigest()}  {name}\n" for name in PAYLOADS))

    def deploy(self, success=True, **extra):
        result = subprocess.run(["bash", str(SCRIPT), str(self.directory), "fixture-api", extra.pop("API_PORT", "49123"), self.env["STUB_REVISION"], str(self.artifact)],
                                env=dict(self.env, **extra), text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_legacy_unchanged()
        self.assert_api_only_commands()
        return result

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def releases(self):
        return sorted((self.directory / "api-releases").glob("*"))

    def assert_legacy_unchanged(self):
        for name, content in self.legacy.items():
            self.assertEqual((self.directory / name).read_bytes(), content, name)

    def assert_api_only_commands(self):
        for command in self.commands():
            args = command["args"]
            if command["tool"] == "curl":
                self.assertEqual(args[-1], "http://127.0.0.1:49123/ready")
                continue
            self.assertEqual(command["web"], "host-web-must-not-change")
            self.assertFalse(set(args) & {"down", "rm", "--remove-orphans", "prune", "web"})
            self.assertNotIn("fixture-web", args)
            if args[0] == "compose":
                self.assertEqual(args[args.index("--project-name") + 1], "fixture-api")
                self.assertEqual(args[args.index("--project-directory") + 1], str(self.directory))
                if "up" in args:
                    self.assertEqual(args[-1], "server")
                    self.assertIn("--no-deps", args)
                    self.assertIn("--no-build", args)
                    self.assertEqual(args[args.index("--pull") + 1], "never")
                if "stop" in args:
                    self.assertEqual(args[-1], "server")
                if "exec" in args:
                    self.assertEqual(args[args.index("-T") + 1], "db")

    def assert_no_container_change(self):
        self.assertFalse(any("up" in c["args"] or "stop" in c["args"] or "load" in c["args"] for c in self.commands()))
        self.assertFalse((self.directory / "current-api-revision").exists())

    def test_success_and_immutable_repeat_snapshots(self):
        self.deploy()
        self.assertEqual((self.directory / "current-api-revision").read_text(), REVISION + "\n")
        self.assertIn("RSRS_SERVER_IMAGE=" + IMAGE_ID, (self.directory / "api-deployment.env").read_text())
        first = self.releases()[0]
        snapshot = {str(path.relative_to(first)): path.read_bytes() for path in first.rglob("*") if path.is_file()}
        self.deploy()
        self.assertEqual(len(self.releases()), 2)
        self.assertEqual(snapshot, {str(path.relative_to(first)): path.read_bytes() for path in first.rglob("*") if path.is_file()})
        self.assertEqual(len(list((self.directory / "backups").glob("*.dump"))), 2)
        self.assertFalse((self.directory / "api-deployment-incomplete").exists())
        commands = self.commands()
        verify = next(i for i, c in enumerate(commands) if "pg_restore" in c["args"])
        stop = next(i for i, c in enumerate(commands) if "stop" in c["args"])
        self.assertLess(verify, stop)

    def test_checksum_failure_has_no_docker_calls(self):
        (self.artifact / "compose-api.yaml").write_text("tampered")
        self.deploy(success=False)
        self.assertEqual(self.commands(), [])

    def test_incomplete_checksum_manifest_rejected(self):
        manifest = self.artifact / "SHA256SUMS"
        manifest.write_text(manifest.read_text().splitlines()[0] + "\n")
        self.deploy(success=False)
        self.assertEqual(self.commands(), [])

    def test_revision_mismatch(self):
        (self.artifact / "server-sha.txt").write_text("d" * 40 + "\n")
        self.checksums()
        self.deploy(success=False)
        self.assertEqual(self.commands(), [])

    def test_missing_restore_marker(self):
        del self.legacy[".migration-verified"]
        (self.directory / ".migration-verified").unlink()
        self.deploy(success=False)
        self.assertEqual(self.commands(), [])

    def test_no_database_never_starts_one(self):
        self.deploy(success=False, STUB_NO_DB="1")
        self.assert_no_container_change()

    def test_extra_compose_service_rejected(self):
        self.deploy(success=False, STUB_SERVICES="db\nserver\nweb")
        self.assert_no_container_change()

    def test_empty_backup_blocks_rollout(self):
        self.deploy(success=False, STUB_EMPTY_DUMP="1")
        self.assert_no_container_change()

    def test_invalid_backup_blocks_rollout(self):
        self.deploy(success=False, STUB_BAD_DUMP="1")
        self.assert_no_container_change()
        self.assertEqual(list((self.directory / "backups").glob("*.dump")), [])

    def test_image_revision_label_mismatch_blocks_stop(self):
        self.deploy(success=False, STUB_LABEL="wrong")
        self.assertFalse(any("stop" in c["args"] or "up" in c["args"] for c in self.commands()))
        self.assertFalse((self.directory / "current-api-revision").exists())

    def test_health_failure_retains_last_good_configuration_and_blocks_retry(self):
        for failure in ("STUB_UP_FAIL", "STUB_CURL_FAIL"):
            with self.subTest(failure=failure):
                # These are separate attempts after a successful explicit rollback.
                self.deploy()
                saved = {name: (self.directory / name).read_bytes() for name in
                         ("compose-api.yaml", "api-deployment.env", "current-api-revision")}
                prior = set(self.releases())
                candidate = ("d" if failure == "STUB_UP_FAIL" else "e") * 40
                self.env["STUB_REVISION"] = candidate
                (self.artifact / "server-sha.txt").write_text(candidate + "\n")
                self.checksums()
                result = self.deploy(success=False, **{failure: "1"})
                release = next(iter(set(self.releases()) - prior))
                for name, contents in saved.items():
                    self.assertEqual((self.directory / name).read_bytes(), contents)
                self.assertIn("No automatic database/image rollback", result.stderr)
                self.assertTrue((release / "ROLLBACK.md").exists())
                self.assertTrue((self.directory / "api-deployment-incomplete").exists())
                before = len(self.commands())
                self.deploy(success=False)
                self.assertEqual(len(self.commands()), before)
                rollback = subprocess.run(["bash", str(release / "rollback-api.sh"), "--schema-compatible"],
                                          env=self.env, text=True, capture_output=True)
                self.assertEqual(rollback.returncode, 0, rollback.stdout + rollback.stderr)
                self.assertFalse((self.directory / "api-deployment-incomplete").exists())
                self.assertIn(OLD_IMAGE_ID, (self.directory / "api-deployment.env").read_text())
                self.assert_legacy_unchanged()
                self.assert_api_only_commands()

    def test_first_rollout_rollback_removes_only_api_marker(self):
        self.deploy()
        self.assertNotIn("ONEMEMORY_SERVER_IMAGE=", (self.directory / "api-deployment.env").read_text())
        result = subprocess.run(["bash", str(self.releases()[0] / "rollback-api.sh"), "--schema-compatible"],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.directory / "current-api-revision").exists())
        self.assertIn(OLD_IMAGE_ID, (self.directory / "api-deployment.env").read_text())
        self.assertIn("ONEMEMORY_SERVER_IMAGE=" + OLD_IMAGE_ID, (self.directory / "api-deployment.env").read_text())
        records = [json.loads(line) for line in self.log.read_text().splitlines()]
        restored = [record for record in records if record.get("tool") == "docker" and "up" in record["args"]]
        self.assertEqual(restored[-1]["legacy_image"], OLD_IMAGE_ID)
        self.assertNotIn("RSRS_WEB", (self.directory / "api-deployment.env").read_text())
        self.assert_legacy_unchanged()
        self.assert_api_only_commands()

    def test_rollback_refuses_env_drift_before_changing_container(self):
        self.deploy()
        (self.directory / ".env").write_text("POSTGRES_PASSWORD=rotated-fixture\n")
        count = len(self.commands())
        result = subprocess.run(["bash", str(self.releases()[0] / "rollback-api.sh"), "--schema-compatible"],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Environment changed since snapshot", result.stderr)
        self.assertEqual(len(self.commands()), count)
        self.assertEqual((self.directory / ".env").read_text(), "POSTGRES_PASSWORD=rotated-fixture\n")

    def test_failed_rollback_leaves_recovery_guard_and_last_good_config(self):
        self.deploy()
        saved = (self.directory / "api-deployment.env").read_bytes()
        result = subprocess.run(["bash", str(self.releases()[0] / "rollback-api.sh"), "--schema-compatible"],
                                env=dict(self.env, STUB_UP_FAIL="1"), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.directory / "api-deployment-incomplete").exists())
        self.assertEqual((self.directory / "api-deployment.env").read_bytes(), saved)
        self.assertEqual((self.directory / "current-api-revision").read_text(), REVISION + "\n")
        self.assert_legacy_unchanged()
        self.assert_api_only_commands()

    def test_concurrent_attempt_refused_without_docker_calls(self):
        with (self.directory / ".api-deployment.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.deploy(success=False)
        self.assertEqual(self.commands(), [])

    def test_missing_legacy_deployment_env_is_not_created(self):
        del self.legacy["deployment.env"]
        (self.directory / "deployment.env").unlink()
        self.deploy()
        self.assertFalse((self.directory / "deployment.env").exists())

    def test_rollback_requires_schema_acknowledgement(self):
        self.deploy()
        count = len(self.commands())
        rollback = subprocess.run(["bash", str(self.releases()[0] / "rollback-api.sh")], env=self.env, capture_output=True)
        self.assertNotEqual(rollback.returncode, 0)
        self.assertEqual(len(self.commands()), count)

    def test_no_previous_server_rollout_supported_but_no_unreviewed_rollback(self):
        self.deploy(STUB_NO_SERVER="1")
        result = subprocess.run(["bash", str(self.releases()[0] / "rollback-api.sh"), "--schema-compatible"],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No previous server image", result.stderr)

    def test_invalid_port_rejected_before_docker_calls(self):
        self.deploy(success=False, API_PORT="65536")
        self.assertEqual(self.commands(), [])


class WorkflowTest(unittest.TestCase):
    def test_workflow_packages_only_api_and_checks_exact_revision(self):
        workflow = (REPO / ".github/workflows/api-deployment-artifact.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertNotIn("\n  pull_request:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("for workflow in ci.yml server-image.yml", workflow)
        self.assertIn('--commit "$GITHUB_SHA" --branch main --event push', workflow)
        self.assertIn("select(.headSha == $sha)", workflow)
        self.assertIn('sort_by(.createdAt) | last', workflow)
        self.assertIn('.status == "completed" and .conclusion == "success"', workflow)
        for forbidden in ("respire-site", "site-sha", "admin-ui", "compose-web", "respire-web", "npm ci"):
            self.assertNotIn(forbidden, workflow)
        self.assertIn('docker save "respire-server:$GITHUB_SHA" | gzip', workflow)
        self.assertIn('org.opencontainers.image.revision=$GITHUB_SHA', workflow)
        self.assertIn("sha256sum " + " ".join(PAYLOADS) + " > SHA256SUMS", workflow)

    def test_safety_suite_runs_for_pull_requests(self):
        workflow = (REPO / ".github/workflows/api-deployment-tests.yml").read_text()
        self.assertIn("pull_request:", workflow)
        self.assertIn("python3 -m unittest discover -s deploy/tests -v", workflow)
        self.assertIn("bash -n deploy/ssh-deploy-api.sh", workflow)


@unittest.skipUnless(shutil.which("jq"), "Workflow gate fixtures require jq (provided on GitHub runners)")
class WorkflowGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="respire-api-gate-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        workflow = (REPO / ".github/workflows/api-deployment-artifact.yml").read_text()
        self.gate = textwrap.dedent(workflow.split("        run: |\n", 1)[1].split("      - name:", 1)[0])
        gh = self.root / "gh"
        gh.write_text("""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['STUB_GH_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
print(json.dumps(json.loads(os.environ['STUB_RUNS'])[args[args.index('--workflow') + 1]]))
""")
        gh.chmod(0o700)
        self.log = self.root / "gh.jsonl"

    def run_record(self):
        return dict(headSha=REVISION, status="completed", conclusion="success",
                    createdAt="2026-10-04T00:00:00Z")

    def check_gate(self, ci, image, success):
        env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}", GITHUB_SHA=REVISION,
                   GITHUB_REPOSITORY="fixture/server", GH_TOKEN="fixture-only",
                   STUB_GH_LOG=str(self.log), STUB_RUNS=json.dumps({"ci.yml": ci, "server-image.yml": image}))
        result = subprocess.run(["bash", "-c", self.gate], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        for call in calls:
            self.assertEqual(call[call.index("--commit") + 1], REVISION)
            self.assertEqual(call[call.index("--branch") + 1], "main")
            self.assertEqual(call[call.index("--event") + 1], "push")
        return calls

    def test_both_exact_successful_workflows_required(self):
        calls = self.check_gate([self.run_record()], [self.run_record()], True)
        self.assertEqual([call[call.index("--workflow") + 1] for call in calls], ["ci.yml", "server-image.yml"])

    def test_missing_ci_refuses_artifact(self):
        self.check_gate([], [self.run_record()], False)

    def test_other_sha_cannot_satisfy_gate(self):
        wrong = self.run_record()
        wrong["headSha"] = "f" * 40
        self.check_gate([wrong], [self.run_record()], False)

    def test_latest_failure_overrides_older_success(self):
        failed = self.run_record()
        failed.update(createdAt="2026-10-04T01:00:00Z", conclusion="failure")
        self.check_gate([failed, self.run_record()], [self.run_record()], False)

    def test_running_rerun_does_not_use_older_success(self):
        running = self.run_record()
        running.update(createdAt="2026-10-04T01:00:00Z", status="in_progress", conclusion=None)
        self.check_gate([self.run_record()], [running, self.run_record()], False)

    def test_failed_server_image_refuses_artifact(self):
        failed = self.run_record()
        failed["conclusion"] = "failure"
        self.check_gate([self.run_record()], [failed], False)


if __name__ == "__main__":
    unittest.main()

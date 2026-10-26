from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "Scripts/simulator-readiness.py"
SPEC = importlib.util.spec_from_file_location("simulator_readiness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(readiness)

OWNED_UDID = "11111111-2222-3333-4444-555555555555"
OTHER_UDID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
PRIVATE_TEXT = "synthetic-private-value-not-for-public-receipt"


def outcome(payload: bytes = b"", reason: str = "COMPLETED") -> dict:
    return {
        "reason": reason,
        "exitCode": 0 if reason == "COMPLETED" else -15,
        "elapsedMilliseconds": 1,
        "outputBytes": len(payload),
        "outputSHA256": hashlib.sha256(payload).hexdigest(),
        "processGroupStopped": True,
        "payload": payload,
    }


class FakeInvoker:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, str], float]] = []
        self.created = False
        self.booted = False
        self.name = ""
        self.failure_action = None
        self.delete_failure = False
        self.bad_runtime = False
        self.bad_device_identity = False

    def catalog(self) -> dict:
        runtime = {
            "identifier": readiness.RUNTIME,
            "version": "27.0",
            "buildversion": "different" if self.bad_runtime else readiness.RUNTIME_BUILD,
            "supportedArchitectures": ["arm64"],
            "isAvailable": True,
        }
        rows = [{"udid": OTHER_UDID, "name": "Unrelated synthetic device"}]
        if self.created:
            rows.append({
                "udid": OWNED_UDID,
                "name": self.name,
                "deviceTypeIdentifier": readiness.DEVICE_TYPE,
                "state": "Booted" if self.booted else "Shutdown",
                "isAvailable": not self.bad_device_identity,
                "dataPath": "/native-synthetic-home/Library/Developer/CoreSimulator/Devices/" + OWNED_UDID + "/data",
            })
        return {
            "runtimes": [runtime],
            "devicetypes": [{"identifier": readiness.DEVICE_TYPE}],
            "devices": {readiness.RUNTIME: rows},
        }

    def __call__(self, arguments: list[str], environment: dict[str, str], timeout: float) -> dict:
        self.calls.append((list(arguments), dict(environment), timeout))
        if arguments == ["/bin/ps", "-axo", "uid=,pid=,comm="]:
            return outcome((str(os.geteuid()) + " 43210 /synthetic/private/com.apple.CoreSimulator.CoreSimulatorService\n").encode("ascii"))
        if arguments[0] == "/usr/bin/openssl":
            if "-out" in arguments:
                Path(arguments[arguments.index("-out") + 1]).write_text(PRIVATE_TEXT, encoding="ascii")
            return outcome(PRIVATE_TEXT.encode("ascii"))
        if arguments[:2] != ["/usr/bin/xcrun", "simctl"]:
            raise AssertionError("unexpected command")
        action = arguments[2]
        if action == self.failure_action or (action == "delete" and self.delete_failure):
            return outcome(PRIVATE_TEXT.encode("ascii"), "TIMEOUT")
        if action == "list":
            return outcome(json.dumps(self.catalog()).encode("ascii"))
        if action == "create":
            self.name, self.created = arguments[3], True
            return outcome((OWNED_UDID + "\n").encode("ascii"))
        if action == "boot":
            self.booted = True
        elif action == "shutdown":
            self.booted = False
        elif action == "delete":
            self.created = False
        return outcome(PRIVATE_TEXT.encode("ascii"))


class SimulatorReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="readiness-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.native = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "DEVELOPER_DIR": readiness.DEVELOPER,
            "HOME": "/native-synthetic-home",
            "TMPDIR": "/native-synthetic-temp/",
            "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
        }

    def make_diagnostic(self, mode="legacy-context", invoker=None):
        invoker = FakeInvoker() if invoker is None else invoker
        root = self.root / mode
        root.mkdir(exist_ok=True)
        diagnostic = readiness.Diagnostic(mode, root, self.native, invoker=invoker)
        return diagnostic, invoker

    def test_environment_comparison_has_same_schedule_and_no_inherited_injection(self) -> None:
        legacy = readiness.environment_plan("legacy-context", self.native, self.root)
        native = readiness.environment_plan("native-context", self.native, self.root)
        self.assertEqual(len(legacy), 4)
        self.assertEqual(len(native), 4)
        self.assertEqual(legacy[0]["HOME"], native[0]["HOME"])
        self.assertEqual(legacy[0]["TMPDIR"], str(self.root.parent) + "/")
        self.assertEqual(native[0]["TMPDIR"], self.native["TMPDIR"])
        self.assertEqual(native, [self.native] * 4)
        self.assertNotIn("CFFIXED_USER_HOME", self.native)
        self.assertEqual(legacy[1]["HOME"], str(self.root / "TechnicalHome"))
        self.assertEqual(legacy[1]["CFFIXED_USER_HOME"], legacy[1]["HOME"])
        self.assertEqual(legacy[2]["HOME"], "/var/empty")
        self.assertNotIn("CFFIXED_USER_HOME", legacy[2])
        self.assertNotIn("TMPDIR", legacy[2])
        self.assertEqual(legacy[3]["HOME"], str(self.root / "RuntimeHome"))
        self.assertEqual(legacy[3]["CFFIXED_USER_HOME"], legacy[3]["HOME"])
        self.assertEqual(legacy[3]["PYTHONNOUSERSITE"], "1")
        self.assertEqual(legacy[3]["PYTHONDONTWRITEBYTECODE"], "1")
        legacy[0]["HOME"] = "changed fixture"
        self.assertEqual(self.native["HOME"], "/native-synthetic-home")
        with self.assertRaises(ValueError):
            readiness.environment_plan("unknown", self.native, self.root)

    def test_both_success_lanes_use_same_command_order_and_preserve_exact_identity(self) -> None:
        reports = []
        command_shapes = []
        for mode in readiness.MODES:
            diagnostic, invoker = self.make_diagnostic(mode)
            report = diagnostic.run()
            self.assertEqual(report["status"], "SIMULATOR PASS")
            self.assertIsNone(report["primaryFailure"])
            self.assertEqual(report["cleanup"]["status"], "PASS")
            self.assertTrue(report["cleanup"]["createdDeviceAbsent"])
            self.assertTrue(report["cleanup"]["ephemeralCAKeyAbsent"])
            self.assertFalse((diagnostic.root / "owned-ca.key").exists())
            self.assertEqual(report["observations"]["deviceDataRootClass"], "NATIVE_HOME")
            self.assertEqual(report["observations"]["runtimeHomeMatchesNativeHome"], mode == "native-context")
            self.assertTrue(all(call[2] > 0 for call in invoker.calls))
            main_rows = {row["stage"]: row for row in report["stages"]}
            self.assertEqual(main_rows["boot"]["timeoutSeconds"], 60)
            self.assertEqual(main_rows["bootstatus"]["timeoutSeconds"], 180)
            self.assertEqual(main_rows["keychain-add-root-cert"]["timeoutSeconds"], 180)
            self.assertEqual(main_rows["identity"]["timeoutSeconds"], 180)
            self.assertEqual(main_rows["listapps"]["timeoutSeconds"], 30)
            self.assertLess(list(main_rows).index("bootstatus"), list(main_rows).index("keychain-add-root-cert"))
            self.assertLess(list(main_rows).index("identity"), list(main_rows).index("listapps"))
            shapes = []
            for command, _, _ in invoker.calls:
                if command[0] == "/usr/bin/xcrun":
                    shapes.append(tuple(
                        "<owned-name>" if value == diagnostic.name else
                        "<owned-id>" if value == OWNED_UDID else
                        "<certificate>" if value.endswith("owned-ca.crt") else value
                        for value in command
                    ))
            command_shapes.append(shapes)
            reports.append(report)
        self.assertEqual(command_shapes[0], command_shapes[1])
        self.assertEqual([r["stage"] for r in reports[0]["stages"]], [r["stage"] for r in reports[1]["stages"]])

    def test_receipt_contains_no_raw_output_paths_identifiers_or_key(self) -> None:
        diagnostic, _ = self.make_diagnostic()
        report = diagnostic.run()
        encoded = json.dumps(report, sort_keys=True)
        for value in (PRIVATE_TEXT, str(diagnostic.root), self.native["HOME"],
                      self.native["TMPDIR"], OWNED_UDID, OTHER_UDID, diagnostic.name,
                      "owned-ca.key", "owned-ca.crt"):
            self.assertNotIn(value, encoded)
        for row in report["stages"] + report["cleanup"]["stages"]:
            self.assertNotIn("payload", row)
            self.assertRegex(row["outputSHA256"], r"^[0-9a-f]{64}$")

    def test_cleanup_deletes_only_returned_owned_target_and_preserves_other_device(self) -> None:
        diagnostic, invoker = self.make_diagnostic()
        report = diagnostic.run()
        deletes = [call[0] for call in invoker.calls if call[0][2:3] == ["delete"]]
        shutdowns = [call[0] for call in invoker.calls if call[0][2:3] == ["shutdown"]]
        self.assertEqual(deletes, [["/usr/bin/xcrun", "simctl", "delete", OWNED_UDID]])
        self.assertEqual(shutdowns, [["/usr/bin/xcrun", "simctl", "shutdown", OWNED_UDID]])
        self.assertEqual(report["cleanup"]["status"], "PASS")
        self.assertEqual([r["udid"] for r in invoker.catalog()["devices"][readiness.RUNTIME]], [OTHER_UDID])

    def test_primary_timeout_and_independent_cleanup_failure_are_both_retained(self) -> None:
        fake = FakeInvoker()
        fake.failure_action, fake.delete_failure = "keychain", True
        diagnostic, invoker = self.make_diagnostic(invoker=fake)
        report = diagnostic.run()
        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["primaryFailure"], {"stage": "keychain-add-root-cert", "reason": "TIMEOUT"})
        self.assertEqual(report["cleanup"]["status"], "BLOCKED")
        self.assertFalse(report["cleanup"]["createdDeviceAbsent"])
        self.assertIn({"stage": "cleanup-delete", "reason": "TIMEOUT"}, report["cleanup"]["errors"])
        self.assertIn({"stage": "cleanup-verify", "reason": "OWNED_DEVICE_REMAINS"}, report["cleanup"]["errors"])
        self.assertTrue(any(call[0][2:3] == ["shutdown"] for call in invoker.calls))
        self.assertTrue(any(row["stage"] == "cleanup-verify" for row in report["cleanup"]["stages"]))

    def test_create_timeout_without_identifier_does_not_claim_cleanup_pass(self) -> None:
        fake = FakeInvoker()
        fake.failure_action = "create"
        diagnostic, invoker = self.make_diagnostic(invoker=fake)
        report = diagnostic.run()
        self.assertEqual(report["primaryFailure"], {"stage": "create", "reason": "TIMEOUT"})
        self.assertEqual(report["cleanup"]["status"], "BLOCKED")
        self.assertIn({"stage": "cleanup-verify", "reason": "CREATE_COMPLETION_UNPROVEN"}, report["cleanup"]["errors"])
        self.assertFalse(any(call[0][2:3] in (["delete"], ["shutdown"]) for call in invoker.calls))

    def test_create_timeout_discovers_and_deletes_only_matching_unique_name(self) -> None:
        fake = FakeInvoker()
        original = fake.__call__

        def late_create(arguments, environment, timeout):
            if arguments[0:3] == ["/usr/bin/xcrun", "simctl", "create"]:
                fake.name, fake.created = arguments[3], True
                fake.calls.append((list(arguments), dict(environment), timeout))
                return outcome(reason="TIMEOUT")
            return original(arguments, environment, timeout)

        diagnostic, _ = self.make_diagnostic(invoker=late_create)
        report = diagnostic.run()
        deletes = [c[0] for c in fake.calls if c[0][2:3] == ["delete"]]
        self.assertEqual(deletes, [["/usr/bin/xcrun", "simctl", "delete", OWNED_UDID]])
        self.assertFalse(fake.created)
        self.assertEqual(report["cleanup"]["status"], "BLOCKED")
        self.assertEqual(report["primaryFailure"], {"stage": "create", "reason": "TIMEOUT"})

    def test_cleanup_discovery_failure_is_reported_even_if_known_target_is_removed(self) -> None:
        fake = FakeInvoker()
        diagnostic, _ = self.make_diagnostic(invoker=fake)
        diagnostic.udid, diagnostic.create_started = OWNED_UDID, True
        fake.name, fake.created = diagnostic.name, True
        original = fake.__call__
        first_catalog = [True]

        def broken_discovery(arguments, environment, timeout):
            if arguments[0:3] == ["/usr/bin/xcrun", "simctl", "list"] and first_catalog[0]:
                first_catalog[0] = False
                fake.calls.append((list(arguments), dict(environment), timeout))
                return outcome(reason="TIMEOUT")
            return original(arguments, environment, timeout)

        diagnostic.invoker = broken_discovery
        cleanup = diagnostic.cleanup()
        self.assertEqual(cleanup["status"], "BLOCKED")
        self.assertTrue(cleanup["createdDeviceAbsent"])
        self.assertIn({"stage": "cleanup-discover", "reason": "TIMEOUT"}, cleanup["errors"])
        self.assertFalse(fake.created)

    def test_invalid_runtime_stops_before_create_and_wrong_identity_blocks_after_boot(self) -> None:
        bad_runtime = FakeInvoker()
        bad_runtime.bad_runtime = True
        diagnostic, fake = self.make_diagnostic(invoker=bad_runtime)
        report = diagnostic.run()
        self.assertEqual(report["primaryFailure"]["reason"], "RUNTIME_MISMATCH")
        self.assertFalse(any(c[0][2:3] == ["create"] for c in fake.calls))
        self.assertEqual(report["cleanup"]["reason"], "NO_CREATE_ATTEMPT")
        bad_identity = FakeInvoker()
        bad_identity.bad_device_identity = True
        diagnostic, _ = self.make_diagnostic("native-context", bad_identity)
        report = diagnostic.run()
        self.assertEqual(report["primaryFailure"], {"stage": "identity", "reason": "DEVICE_IDENTITY_MISMATCH"})
        self.assertEqual(report["cleanup"]["status"], "PASS")

    def test_exhausted_main_deadline_does_not_consume_cleanup_budget(self) -> None:
        now = [0.0]
        fake = FakeInvoker()
        diagnostic = readiness.Diagnostic("legacy-context", self.root, self.native,
                                          invoker=fake, clock=lambda: now[0])
        diagnostic.udid, diagnostic.create_started = OWNED_UDID, True
        fake.created, fake.name = True, diagnostic.name
        now[0] = readiness.MAIN_BUDGET + 1
        with self.assertRaises(readiness.DiagnosticFailure) as failure:
            diagnostic.command("bounded-stage", ["must-not-run"], self.native, 30)
        self.assertEqual(failure.exception.reason, "SHARED_DEADLINE")
        self.assertEqual(fake.calls, [])
        cleanup = diagnostic.cleanup()
        self.assertEqual(cleanup["status"], "PASS")
        self.assertTrue(cleanup["createdDeviceAbsent"])
        self.assertTrue(all(0 < timeout <= 30 for _, _, timeout in fake.calls))

    def test_invoke_timeout_stops_descendant_holding_output_pipe(self) -> None:
        pid_file = self.root / "descendant.pid"
        child = "import time; time.sleep(30)"
        parent = (
            "import pathlib,subprocess,sys; "
            "p=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid))"
        )
        environment = {"PATH": "/usr/bin:/bin"}
        started = time.monotonic()
        result = readiness.invoke([sys.executable, "-c", parent, str(pid_file), child], environment, 0.5)
        self.assertEqual(result["reason"], "TIMEOUT")
        self.assertTrue(result["processGroupStopped"])
        self.assertLess(time.monotonic() - started, 6)
        self.assertTrue(pid_file.is_file())
        pid = pid_file.read_text(encoding="ascii")
        for _ in range(30):
            state = subprocess.run(["/bin/ps", "-p", pid, "-o", "stat="],
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=2).stdout.strip()
            if not state or state.startswith("Z"):
                break
            time.sleep(0.05)
        else:
            self.fail("descendant survived timed-out process group")

    def test_invoke_output_bound_does_not_export_oversized_output(self) -> None:
        with mock.patch.object(readiness, "OUTPUT_LIMIT", 64):
            result = readiness.invoke([sys.executable, "-c", "print('x'*100000)"],
                                      {"PATH": "/usr/bin:/bin"}, 2)
        self.assertEqual(result["reason"], "OUTPUT_BOUND")
        self.assertTrue(result["processGroupStopped"])
        self.assertLessEqual(result["outputBytes"], 64)
        self.assertEqual(result["outputSHA256"], hashlib.sha256(result["payload"]).hexdigest())

    def test_group_census_is_exact_and_unavailable_data_never_proves_absence(self) -> None:
        for payload, expected in (
            (b"123 S\n456 S\n", True),
            (b"123 Z\n456 S\n", False),
            (b"456 S\n", False),
            (b"malformed private output\n", None),
        ):
            with self.subTest(payload=payload):
                result = subprocess.CompletedProcess(["ps"], 0, stdout=payload)
                with mock.patch.object(readiness.subprocess, "run", return_value=result):
                    self.assertIs(readiness.live_group_members(123), expected)
        result = subprocess.CompletedProcess(["ps"], 1, stdout=b"")
        with mock.patch.object(readiness.subprocess, "run", return_value=result):
            self.assertIsNone(readiness.live_group_members(123))

    def test_unavailable_group_census_is_not_reported_as_successful_cleanup(self) -> None:
        process = mock.Mock()
        process.pid = 123456789
        process.poll.return_value = 0
        with (
            mock.patch.object(readiness.os, "killpg"),
            mock.patch.object(readiness, "live_group_members", return_value=None),
        ):
            self.assertFalse(readiness.stop_group(process))

    def test_host_guard_blocks_local_execution_before_any_simulator_command(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", [str(SCRIPT), "--mode", "legacy-context", "--work-root", str(self.root / "must-not-exist")]),
            mock.patch.dict(os.environ, {"HOME": self.native["HOME"], "GITHUB_ACTIONS": "false"}, clear=True),
            mock.patch.object(readiness, "invoke") as invoker,
            mock.patch("sys.stdout", output),
        ):
            exit_code = readiness.main()
        invoker.assert_not_called()
        self.assertEqual(exit_code, 1)
        self.assertFalse((self.root / "must-not-exist").exists())
        line = output.getvalue()
        self.assertTrue(line.startswith("READINESS-RECEIPT "))
        receipt = json.loads(line.removeprefix("READINESS-RECEIPT "))
        self.assertEqual(receipt["primaryFailure"], {"stage": "host-preflight", "reason": "HOST_MISMATCH"})
        self.assertNotIn(str(self.root), line)

    def test_native_policy_loader_rejects_changed_bytes_before_execution(self) -> None:
        policy = self.root / "substituted-policy.py"
        policy.write_text("raise AssertionError('must not execute')\n", encoding="ascii")
        with self.assertRaises(readiness.DiagnosticFailure) as mismatch:
            readiness.load_native_policy_environment(policy)
        self.assertEqual(mismatch.exception.reason, "POLICY_HASH_MISMATCH")
        linked = self.root / "linked-policy.py"
        linked.symlink_to(policy)
        with self.assertRaises(readiness.DiagnosticFailure) as symlink:
            readiness.load_native_policy_environment(linked)
        self.assertEqual(symlink.exception.reason, "POLICY_FILE_INVALID")

    def test_exact_native_policy_ignores_overridden_parent_context(self) -> None:
        developer = self.root / "synthetic-developer"
        developer.mkdir()
        policy = SCRIPT.with_name("native_simulator_environment.py")
        with (
            mock.patch.object(readiness, "DEVELOPER", str(developer)),
            mock.patch.dict(os.environ, {"HOME": "/synthetic-overridden-home", "TMPDIR": "/synthetic-overridden-temp", "CFFIXED_USER_HOME": "/synthetic-overridden-cf"}, clear=True),
        ):
            environment = readiness.load_native_policy_environment(policy)
        self.assertEqual(environment["HOME"], readiness.pwd.getpwuid(os.geteuid()).pw_dir)
        self.assertEqual(environment["TMPDIR"], os.confstr(65537))
        self.assertNotIn("CFFIXED_USER_HOME", environment)


if __name__ == "__main__":
    unittest.main()

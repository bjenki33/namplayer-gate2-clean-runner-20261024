#!/usr/bin/env python3
"""Synthetic CoreSimulator environment comparison; not a NamPlayer gate proof."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import selectors
import signal
import subprocess
import sys
import time


DEVELOPER = "/Applications/Xcode_27.0.app/Contents/Developer"
RUNTIME = "com.apple.CoreSimulator.SimRuntime.iOS-27-0"
DEVICE_TYPE = "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"
IMAGE_VERSION = "20261023.0307.1"
RUNTIME_BUILD = "24A434"
OUTPUT_LIMIT = 2 * 1024 * 1024
MAIN_BUDGET = 900
CLEANUP_BUDGET = 180
UUID_RE = re.compile(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}")
MODES = ("legacy-context", "native-context")
NATIVE_POLICY_SHA256 = "4c4dcef41aebf75ac96268912f2de40e6a07775ab0c4ca92fb70e280a878c798"


class DiagnosticFailure(Exception):
    def __init__(self, stage: str, reason: str) -> None:
        super().__init__(reason)
        self.stage = stage
        self.reason = reason


def load_native_policy_environment(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise DiagnosticFailure("native-policy", "POLICY_FILE_INVALID")
    if hashlib.sha256(path.read_bytes()).hexdigest() != NATIVE_POLICY_SHA256:
        raise DiagnosticFailure("native-policy", "POLICY_HASH_MISMATCH")
    spec = importlib.util.spec_from_file_location("confirmed_native_simulator_policy", path)
    if spec is None or spec.loader is None:
        raise DiagnosticFailure("native-policy", "POLICY_LOAD_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.native_environment(Path(DEVELOPER))


def live_group_members(group: int) -> bool | None:
    """Return None when an independent, bounded group census is unavailable."""
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pgid=,stat="], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.decode("ascii", errors="replace").splitlines():
            fields = line.split()
            if len(fields) != 2 or not fields[0].isdigit():
                return None
            if int(fields[0]) == group and not fields[1].startswith("Z"):
                return True
        return False
    except (OSError, subprocess.SubprocessError):
        return None


def stop_group(process: subprocess.Popen[bytes]) -> bool:
    """Stop a command and any descendants still holding its pipes open."""
    ok = True
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        except OSError:
            ok = False
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if signum == signal.SIGKILL:
                ok = False
        if live_group_members(process.pid) is False:
            return process.poll() is not None
    return ok and live_group_members(process.pid) is False


def invoke(arguments: list[str], environment: dict[str, str], timeout: float) -> dict:
    """Bound time/output and retain only bytes in memory, never print them."""
    started = time.monotonic()
    output = bytearray()
    code = None
    reason = "EXECUTION_ERROR"
    group_stopped = True
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            arguments, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
        )
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = started + timeout
        eof = False
        while not eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "TIMEOUT"
                break
            if not selector.select(min(remaining, 0.2)):
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                eof = True
                continue
            if len(output) + len(chunk) > OUTPUT_LIMIT:
                reason = "OUTPUT_BOUND"
                break
            output.extend(chunk)
        if eof:
            try:
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                reason = "COMPLETED" if code == 0 else "NONZERO_EXIT"
            except subprocess.TimeoutExpired:
                reason = "TIMEOUT"
        if reason not in ("COMPLETED", "NONZERO_EXIT"):
            group_stopped = stop_group(process)
            code = process.returncode
    except (OSError, subprocess.SubprocessError):
        if process is not None:
            group_stopped = stop_group(process)
            code = process.returncode
    finally:
        selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()
    payload = bytes(output)
    return {
        "reason": reason, "exitCode": code,
        "elapsedMilliseconds": round((time.monotonic() - started) * 1000),
        "outputBytes": len(payload), "outputSHA256": hashlib.sha256(payload).hexdigest(),
        "processGroupStopped": group_stopped, "payload": payload,
    }


def read_catalog(payload: bytes, stage: str) -> dict:
    try:
        value = json.loads(payload)
    except (ValueError, UnicodeError):
        raise DiagnosticFailure(stage, "CATALOG_INVALID") from None
    if not isinstance(value, dict):
        raise DiagnosticFailure(stage, "CATALOG_INVALID")
    return value


def verify_runtime(catalog: dict, stage: str) -> None:
    rows = catalog.get("runtimes", [])
    matches = [r for r in rows if isinstance(r, dict) and r.get("identifier") == RUNTIME]
    if len(matches) != 1 or any(matches[0].get(k) != v for k, v in {
        "version": "27.0", "buildversion": RUNTIME_BUILD,
        "supportedArchitectures": ["arm64"], "isAvailable": True,
    }.items()):
        raise DiagnosticFailure(stage, "RUNTIME_MISMATCH")


def device_rows(catalog: dict, stage: str) -> list[dict]:
    devices = catalog.get("devices")
    if not isinstance(devices, dict) or any(
        not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows)
        for rows in devices.values()
    ):
        raise DiagnosticFailure(stage, "DEVICE_CATALOG_INVALID")
    return [r for rows in devices.values() for r in rows]


def environment_plan(mode: str, native: dict[str, str], root: Path) -> list[dict[str, str]]:
    """Same probe schedule, differing only in the environment strategy."""
    if mode not in MODES:
        raise ValueError("unsupported diagnostic mode")
    runtime = dict(native)
    if mode == "native-context":
        return [dict(native) for _ in range(4)]
    technical = dict(native)
    technical.update(HOME=str(root / "TechnicalHome"),
                     CFFIXED_USER_HOME=str(root / "TechnicalHome"),
                     TMPDIR=str(root / "TechnicalTemp") + "/")
    probe = {k: native[k] for k in ("PATH", "DEVELOPER_DIR", "LC_ALL", "LANG")}
    probe["HOME"] = "/var/empty"
    runtime.update(HOME=str(root / "RuntimeHome"),
                   CFFIXED_USER_HOME=str(root / "RuntimeHome"),
                   TMPDIR=str(root / "RuntimeTemp"))
    preflight = dict(native)
    preflight["TMPDIR"] = str(root.parent) + "/"
    runtime.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
    return [preflight, technical, probe, runtime]


class Diagnostic:
    def __init__(self, mode: str, root: Path, native: dict[str, str], *,
                 invoker=invoke, clock=time.monotonic) -> None:
        self.mode, self.root, self.native = mode, root, native
        self.invoker, self.clock = invoker, clock
        self.plan = environment_plan(mode, native, root)
        self.runtime_environment = self.plan[-1]
        self.name = "NamPlayer Readiness " + secrets.token_hex(16)
        self.udid = None
        self.create_started = False
        self.main_deadline = self.clock() + MAIN_BUDGET
        self.rows: list[dict] = []
        self.cleanup_rows: list[dict] = []
        self.observations: dict = {}

    def observe_services(self, label: str) -> None:
        result = self.invoker(["/bin/ps", "-axo", "uid=,pid=,comm="], self.native, 5)
        snapshot = {"available": result["reason"] == "COMPLETED"}
        if snapshot["available"]:
            owners = []
            for line in result["payload"].decode("utf-8", errors="replace").splitlines():
                fields = line.split(maxsplit=2)
                if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
                    if fields[2].rsplit("/", 1)[-1] == "com.apple.CoreSimulator.CoreSimulatorService":
                        owners.append(int(fields[0]))
            snapshot.update(serviceCount=len(owners),
                            allServiceUIDsMatchCurrentUser=bool(owners) and all(uid == os.geteuid() for uid in owners))
        self.observations[label] = snapshot

    def command(self, stage: str, arguments: list[str], environment: dict[str, str],
                seconds: int, *, cleanup=False, check=True) -> bytes:
        deadline = self.cleanup_deadline if cleanup else self.main_deadline
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise DiagnosticFailure(stage, "SHARED_DEADLINE")
        outcome = self.invoker(arguments, environment, min(seconds, remaining))
        wire = {k: v for k, v in outcome.items() if k != "payload"}
        wire.update(stage=stage, timeoutSeconds=seconds,
                    status="PASS" if outcome["reason"] == "COMPLETED" else "FAIL")
        (self.cleanup_rows if cleanup else self.rows).append(wire)
        if outcome["reason"] != "COMPLETED" and (
            check or outcome["reason"] != "NONZERO_EXIT"
        ):
            raise DiagnosticFailure(stage, outcome["reason"])
        if not outcome["processGroupStopped"]:
            raise DiagnosticFailure(stage, "COMMAND_CLEANUP_FAILED")
        return outcome["payload"]

    def simctl(self, stage: str, arguments: list[str], seconds: int, *,
               environment=None, cleanup=False, check=True) -> bytes:
        return self.command(stage, ["/usr/bin/xcrun", "simctl", *arguments],
                            self.runtime_environment if environment is None else environment,
                            seconds, cleanup=cleanup, check=check)

    def create_certificate(self) -> Path:
        config = self.root / "owned-ca.cnf"
        config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3_ca\n"
            "[dn]\nCN=NamPlayer Gate2 Ephemeral CA\n[v3_ca]\n"
            "basicConstraints=critical,CA:TRUE,pathlen:0\n"
            "keyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n",
            encoding="ascii",
        )
        key, cert = self.root / "owned-ca.key", self.root / "owned-ca.crt"
        self.command("ca-key-generation", ["/usr/bin/openssl", "genrsa", "-out", str(key), "2048"], self.native, 30)
        self.command("ca-certificate-generation", [
            "/usr/bin/openssl", "req", "-x509", "-new", "-sha256", "-days", "1",
            "-key", str(key), "-out", str(cert), "-config", str(config),
        ], self.native, 30)
        return cert

    def main_sequence(self) -> None:
        cert = self.create_certificate()
        for label, env in zip(("native-preflight", "technical-context"), self.plan[:2]):
            catalog = read_catalog(self.simctl(label + "-runtimes", ["list", "-j", "runtimes"], 30, environment=env), label)
            verify_runtime(catalog, label)
            catalog = read_catalog(self.simctl(label + "-device-types", ["list", "-j", "devicetypes"], 30, environment=env), label)
            if sum(isinstance(r, dict) and r.get("identifier") == DEVICE_TYPE for r in catalog.get("devicetypes", [])) != 1:
                raise DiagnosticFailure(label, "DEVICE_TYPE_MISMATCH")
        catalog = read_catalog(self.simctl("fresh-toolchain-context", ["list", "-j", "runtimes", "devicetypes"], 30, environment=self.plan[2]), "fresh-toolchain-context")
        verify_runtime(catalog, "fresh-toolchain-context")
        catalog = read_catalog(self.simctl("runtime-precreate-catalog", ["list", "-j"], 30), "runtime-precreate-catalog")
        if any(r.get("name") == self.name for r in device_rows(catalog, "runtime-precreate-catalog")):
            raise DiagnosticFailure("runtime-precreate-catalog", "NAME_COLLISION")
        self.create_started = True
        payload = self.simctl("create", ["create", self.name, DEVICE_TYPE, RUNTIME], 30)
        candidate = payload.decode("ascii", errors="replace").strip()
        if UUID_RE.fullmatch(candidate) is None:
            raise DiagnosticFailure("create", "INVALID_DEVICE_IDENTIFIER")
        self.udid = candidate
        catalog = read_catalog(self.simctl("runtime-postcreate-catalog", ["list", "-j"], 30), "runtime-postcreate-catalog")
        rows = [r for r in device_rows(catalog, "runtime-postcreate-catalog") if r.get("name") == self.name]
        if len(rows) != 1 or rows[0].get("udid") != self.udid:
            raise DiagnosticFailure("runtime-postcreate-catalog", "CREATE_IDENTITY_MISMATCH")
        self.observations["deviceDataRootClass"] = self.path_class(rows[0].get("dataPath"))
        self.observations["runtimeHomeMatchesNativeHome"] = self.runtime_environment["HOME"] == self.native["HOME"]
        self.simctl("boot", ["boot", self.udid], 60)
        self.simctl("bootstatus", ["bootstatus", self.udid, "-b"], 180)
        self.simctl("keychain-add-root-cert", ["keychain", self.udid, "add-root-cert", str(cert)], 180)
        catalog = read_catalog(self.simctl("identity", ["list", "-j"], 180), "identity")
        verify_runtime(catalog, "identity")
        rows = [r for r in device_rows(catalog, "identity") if r.get("udid") == self.udid]
        runtime_rows = catalog.get("devices", {}).get(RUNTIME, [])
        if len(rows) != 1 or rows[0] not in runtime_rows or any(rows[0].get(k) != v for k, v in {
            "name": self.name, "deviceTypeIdentifier": DEVICE_TYPE,
            "state": "Booted", "isAvailable": True,
        }.items()):
            raise DiagnosticFailure("identity", "DEVICE_IDENTITY_MISMATCH")
        data_path = rows[0].get("dataPath")
        self.observations["deviceDataRootClass"] = self.path_class(data_path)
        self.observations["runtimeHomeMatchesNativeHome"] = self.runtime_environment["HOME"] == self.native["HOME"]
        self.simctl("listapps", ["listapps", self.udid], 30)

    def path_class(self, value: object) -> str:
        if not isinstance(value, str) or not Path(value).is_absolute():
            return "UNAVAILABLE"
        path = Path(value)
        if path.is_relative_to(Path(self.native["HOME"])):
            return "NATIVE_HOME"
        if path.is_relative_to(self.root):
            return "DIAGNOSTIC_WORKSPACE"
        return "OTHER"

    def cleanup(self) -> dict:
        self.cleanup_deadline = self.clock() + CLEANUP_BUDGET
        errors = []
        targets = {self.udid} if self.udid is not None else set()
        if not self.create_started:
            return {"status": "PASS", "reason": "NO_CREATE_ATTEMPT", "stages": [], "createdDeviceAbsent": True}
        try:
            catalog = read_catalog(self.simctl("cleanup-discover", ["list", "-j"], 30, cleanup=True), "cleanup-discover")
            for row in device_rows(catalog, "cleanup-discover"):
                if row.get("name") == self.name:
                    value = row.get("udid")
                    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
                        raise DiagnosticFailure("cleanup-discover", "INVALID_DEVICE_IDENTIFIER")
                    targets.add(value)
        except DiagnosticFailure as error:
            errors.append({"stage": error.stage, "reason": error.reason})
        for target in sorted(targets):
            for stage, args in (
                ("cleanup-shutdown", ["shutdown", target]),
                ("cleanup-delete", ["delete", target]),
            ):
                try:
                    self.simctl(stage, args, 30, cleanup=True, check=False)
                except DiagnosticFailure as error:
                    errors.append({"stage": error.stage, "reason": error.reason})
        absent = False
        try:
            catalog = read_catalog(self.simctl("cleanup-verify", ["list", "-j"], 30, cleanup=True), "cleanup-verify")
            rows = device_rows(catalog, "cleanup-verify")
            absent = not any(r.get("name") == self.name or r.get("udid") in targets for r in rows)
            if not absent:
                errors.append({"stage": "cleanup-verify", "reason": "OWNED_DEVICE_REMAINS"})
            if self.udid is None:
                # A timed-out create may finish late. Do not claim proven absence.
                errors.append({"stage": "cleanup-verify", "reason": "CREATE_COMPLETION_UNPROVEN"})
        except DiagnosticFailure as error:
            errors.append({"stage": error.stage, "reason": error.reason})
        return {"status": "PASS" if absent and not errors else "BLOCKED",
                "createdDeviceAbsent": absent, "errors": errors, "stages": self.cleanup_rows}

    def run(self) -> dict:
        failure = None
        try:
            self.observe_services("serviceBeforeControl")
            self.main_sequence()
        except DiagnosticFailure as error:
            failure = {"stage": error.stage, "reason": error.reason}
        except Exception:
            failure = {"stage": "diagnostic-internal", "reason": "INTERNAL_ERROR"}
        finally:
            try:
                self.observe_services("serviceAfterControl")
            except Exception:
                self.observations["serviceAfterControl"] = {"available": False}
            try:
                cleanup = self.cleanup()
            except Exception:
                cleanup = {"status": "BLOCKED", "reason": "CLEANUP_INTERNAL_ERROR",
                           "createdDeviceAbsent": False, "stages": self.cleanup_rows}
            secret = self.root / "owned-ca.key"
            try:
                if secret.is_file() and not secret.is_symlink():
                    secret.unlink()
                cleanup["ephemeralCAKeyAbsent"] = not os.path.lexists(secret)
            except OSError:
                cleanup["ephemeralCAKeyAbsent"] = False
            if not cleanup["ephemeralCAKeyAbsent"]:
                cleanup["status"] = "BLOCKED"
        return {"schemaVersion": 1, "classification": "gate2-synthetic-simulator-readiness",
                "scope": "environment-diagnostic-only", "mode": self.mode,
                "status": "SIMULATOR PASS" if failure is None and cleanup["status"] == "PASS" else "BLOCKED",
                "primaryFailure": failure, "stages": self.rows,
                "observations": self.observations, "cleanup": cleanup}


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--native-policy", type=Path)
    arguments = parser.parse_args()
    receipt = {"schemaVersion": 1, "classification": "gate2-synthetic-simulator-readiness",
               "scope": "environment-diagnostic-only", "mode": arguments.mode,
               "status": "BLOCKED", "primaryFailure": {"stage": "host-preflight", "reason": "HOST_MISMATCH"}}
    try:
        account = pwd.getpwuid(os.geteuid())
        native_home = Path(account.pw_dir)
        image = os.environ.get("ImageVersion", "")
        if (os.geteuid() < 501 or platform.machine() != "arm64"
                or os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
                or os.environ.get("ImageOS") != "macos27" or image != IMAGE_VERSION
                or (arguments.native_policy is None and
                    Path(os.environ.get("HOME", "")).resolve() != native_home.resolve())):
            raise DiagnosticFailure("host-preflight", "HOST_MISMATCH")
        root = arguments.work_root
        if not root.is_absolute() or os.path.lexists(root):
            raise DiagnosticFailure("host-preflight", "WORKSPACE_NOT_ABSENT")
        root.mkdir(mode=0o700)
        for name in ("TechnicalHome", "TechnicalTemp", "RuntimeHome", "RuntimeTemp"):
            (root / name).mkdir(mode=0o700)
        if arguments.native_policy is None:
            native = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "DEVELOPER_DIR": DEVELOPER,
                      "HOME": str(native_home), "TMPDIR": os.environ["TMPDIR"],
                      "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
        else:
            if arguments.mode != "native-context":
                raise DiagnosticFailure("native-policy", "POLICY_MODE_INVALID")
            native = load_native_policy_environment(arguments.native_policy)
        version = invoke(["/usr/bin/xcodebuild", "-version"], native, 30)
        if version["reason"] != "COMPLETED" or version["payload"].strip() != b"Xcode 27.0\nBuild version 27A266a":
            raise DiagnosticFailure("host-preflight", "XCODE_MISMATCH")
        build = invoke(["/usr/sbin/sysctl", "-n", "kern.osversion"], native, 10)
        build_text = build["payload"].decode("ascii", errors="replace").strip()
        if build["reason"] != "COMPLETED" or build_text != "26A434":
            raise DiagnosticFailure("host-preflight", "MACOS_BUILD_MISMATCH")
        source_commit = os.environ.get("GITHUB_SHA", "")
        if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
            raise DiagnosticFailure("host-preflight", "SOURCE_COMMIT_INVALID")
        receipt = Diagnostic(arguments.mode, root, native).run()
        if arguments.native_policy is not None:
            receipt["nativeEnvironmentPolicySHA256"] = NATIVE_POLICY_SHA256
            receipt["parentContext"] = {
                "homeOverridden": Path(os.environ.get("HOME", "")).resolve() != Path(native["HOME"]).resolve(),
                "temporaryOverridden": Path(os.environ.get("TMPDIR", "")).resolve() != Path(native["TMPDIR"]).resolve(),
                "cfHomeOverridePresent": "CFFIXED_USER_HOME" in os.environ,
            }
        receipt["sourceCommit"] = source_commit
        receipt["host"] = {"runnerImageVersion": image, "imageOS": "macos27",
                           "architecture": "arm64", "xcodeVersion": "27.0",
                           "xcodeBuild": "27A266a", "runtimeBuild": RUNTIME_BUILD,
                           "macOSVersion": platform.mac_ver()[0], "macOSBuild": build_text,
                           "effectiveUIDClass": "NON_ROOT"}
    except DiagnosticFailure as error:
        receipt["primaryFailure"] = {"stage": error.stage, "reason": error.reason}
    except Exception:
        receipt["primaryFailure"] = {"stage": "host-preflight", "reason": "INTERNAL_ERROR"}
    print("READINESS-RECEIPT " + json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["status"] == "SIMULATOR PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

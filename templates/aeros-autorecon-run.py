#!/usr/bin/env python3
"""Run AutoRecon while atomically publishing an optional AEROS run manifest.

This is a Kali-side helper, not a daemon or AEROS backend. AutoRecon remains the
child process. Its scanner exit status is preserved (using the usual 128+signal
convention), while a verified-transport failure is exposed separately as a
wrapper failure without deleting the recoverable scanner output.
"""

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import uuid


SCHEMA_VERSION = 1
MANIFEST_NAME = "aeros-autorecon-run.json"
VERSION_PATTERN = re.compile(r"AutoRecon\s+v?([0-9]+(?:\.[0-9]+){1,3}(?:[-+._A-Za-z0-9]*)?)", re.I)
LAYOUT_FLAGS = {
    "singleTarget": "--single-target",
    "onlyScansDir": "--only-scans-dir",
    "noPortDirs": "--no-port-dirs",
}
WINDOWS_INVALID_COMPONENT = set('<>:"/\\|?*')
WINDOWS_RESERVED_COMPONENTS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
TRANSPORT_INCOMING_PREFIX = ".aeros-transport-incoming"
REDACTED_ARGUMENT = "[REDACTED]"
SENSITIVE_OPTION_PATTERN = re.compile(
    r"(?:^|[-_.])(?:api[-_.]?key|access[-_.]?key|private[-_.]?key|session[-_.]?key|"
    r"auth[-_.]?token|client[-_.]?secret|password|passwd|pass|token|secret|"
    r"credentials?|credential|cred|key)$",
    re.I,
)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_component(value, label):
    text = str(value or "").strip()
    if not text or text in {".", ".."} or len(text) > 200 or any(ord(char) < 32 for char in text) or "/" in text or "\\" in text:
        raise ValueError(f"{label} is empty or unsafe")
    return text


def windows_physical_component(value, label, encoded_prefix):
    """Return a component that can be copied into a Windows-backed tree."""
    text = safe_component(value, label)
    stem = text.split(".", 1)[0].upper()
    unsafe = (
        any(char in WINDOWS_INVALID_COMPONENT for char in text)
        or text.endswith((" ", "."))
        or stem in WINDOWS_RESERVED_COMPONENTS
    )
    if not unsafe:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]
    return f"{encoded_prefix}-{digest}"


def normalized_ip(value):
    text = str(value or "").strip().strip("[]")
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as error:
        raise ValueError(f"invalid resolved IP: {value}") from error


def physical_directory(original, resolved):
    candidate = str(original).strip()
    is_ipv6 = ":" in candidate or ":" in str(resolved or "")
    if is_ipv6:
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:24]
        return f"aeros-ipv6-{digest}"
    return windows_physical_component(candidate, "target physical directory", "aeros-target")


def target_descriptor(value):
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("--target cannot be empty")
    original, separator, resolved = raw.partition("=")
    if "/" in original:
        raise ValueError("CIDR targets are not supported by the manifest wrapper; list exact targets explicitly")
    original = safe_component(original, "original target")
    resolved_ip = normalized_ip(resolved) if separator else normalized_ip(original) if _is_ip(original) else ""
    if not resolved_ip and not _is_ip(original):
        raise ValueError(f"hostname target {original!r} requires an authoritative mapping: --target {original}=RESOLVED_IP")
    return {
        "originalTarget": original,
        "resolvedIp": resolved_ip,
        "physicalDirectory": physical_directory(original, resolved_ip),
    }


def _is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip().strip("[]"))
        return True
    except ValueError:
        return False


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    payload = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
        try:
            descriptor = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except (AttributeError, OSError):
            pass
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def autorecon_version(command):
    probe = [command[0], "--version"]
    try:
        result = subprocess.run(probe, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(f"could not execute {' '.join(probe)}: {error}") from error
    match = VERSION_PATTERN.search(result.stdout or "")
    if result.returncode != 0 or not match:
        raise ValueError(f"could not determine AutoRecon version from {command[0]!r}")
    return match.group(1)


def has_output_option(command):
    return any(value in {"-o", "--output"} or value.startswith("--output=") for value in command[1:])


def validated_command(raw, targets, output_root):
    command = list(raw)
    if not command:
        raise ValueError("provide the AutoRecon command after --")
    if has_output_option(command):
        raise ValueError("do not pass -o/--output; the wrapper owns the unique authorized output root")
    if "--version" in command or "-l" in command or "--list" in command:
        raise ValueError("the wrapped command must be a scan, not a version or plugin-list operation")
    if "--single-target" in command and len(targets) != 1:
        raise ValueError("--single-target requires exactly one manifest --target")
    if "-t" not in command and "--target-file" not in command:
        missing = [row["originalTarget"] for row in targets if row["originalTarget"] not in command]
        if missing:
            raise ValueError(f"manifest target is not present as an exact AutoRecon argument: {missing[0]}")
    return [command[0], "--output", str(output_root), *command[1:]]


def command_manifest_view(command):
    """Return a deterministic manifest-safe command without retaining secrets."""
    original = [str(value) for value in command]
    redacted = []
    redact_next = False
    for value in original:
        if redact_next:
            redacted.append(REDACTED_ARGUMENT)
            redact_next = False
            continue
        option, separator, _option_value = value.partition("=")
        if value.startswith("-") and separator and SENSITIVE_OPTION_PATTERN.search(option.lstrip("-")):
            redacted.append(f"{option}={REDACTED_ARGUMENT}")
            continue
        redacted.append(value)
        if value.startswith("-") and SENSITIVE_OPTION_PATTERN.search(value.lstrip("-")):
            redact_next = True
    material = json.dumps(original, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return {
        "argv": redacted,
        "display": shlex.join(redacted),
        "argvSha256": hashlib.sha256(material).hexdigest(),
        "redacted": redacted != original,
    }


def durable_recovery_base():
    configured = str(os.environ.get("AEROS_AUTORECON_RECOVERY_ROOT") or "").strip()
    return Path(configured).expanduser() if configured else Path.home() / ".local" / "state" / "aeros" / "autorecon-recovery"


def create_recovery_root(run_id):
    base = durable_recovery_base().resolve()
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = Path(tempfile.mkdtemp(prefix=f"run-{run_id}-", dir=str(base))).resolve()
    try:
        root.chmod(0o700)
    except OSError:
        pass
    return root


def _inside(candidate, root):
    candidate = Path(candidate).resolve(strict=True)
    root = Path(root).resolve(strict=True)
    return candidate == root or root in candidate.parents


def _special_kind(mode):
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "special-file"


def inspect_transport_tree(source_root):
    """Inventory regular files without following scanner-created links."""
    source_root = Path(source_root).resolve(strict=True)
    files = []
    directories = []
    diagnostics = []

    def reject(relative, kind, message):
        diagnostics.append({"path": relative.as_posix(), "kind": kind, "message": message})

    def visit(directory, relative_directory=Path()):
        try:
            entries = sorted(os.scandir(directory), key=lambda row: row.name)
        except OSError as error:
            reject(relative_directory, "directory-read-error", str(error))
            return
        for entry in entries:
            relative = relative_directory / entry.name
            path = Path(entry.path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                reject(relative, "lstat-error", str(error))
                continue
            if stat.S_ISLNK(metadata.st_mode):
                reject(relative, "symbolic-link", "Symbolic links are never dereferenced during encoded transport.")
                continue
            try:
                if not _inside(path, source_root):
                    reject(relative, "source-escape", "The resolved source entry is outside the child AutoRecon output root.")
                    continue
            except (OSError, RuntimeError) as error:
                reject(relative, "source-resolution-error", str(error))
                continue
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(relative)
                visit(path, relative)
            elif stat.S_ISREG(metadata.st_mode):
                files.append({"source": path, "relative": relative, "size": int(metadata.st_size)})
            else:
                kind = _special_kind(metadata.st_mode)
                reject(relative, kind, f"Unsupported {kind} entries are not copied.")

    visit(source_root)
    return {"files": files, "directories": directories, "diagnostics": diagnostics}


def transport_relative_path(relative, targets, single_target):
    parts = list(Path(relative).parts)
    if not parts:
        raise ValueError("transported output path is empty")
    if single_target:
        parts.insert(0, targets[0]["physicalDirectory"])
    else:
        mappings = {row["originalTarget"]: row["physicalDirectory"] for row in targets}
        parts[0] = mappings.get(parts[0], parts[0])
        if ":" in parts[0]:
            parts[0] = f"aeros-unmapped-{hashlib.sha256(parts[0].encode('utf-8')).hexdigest()[:24]}"
    for component in parts:
        safe_component(component, "transported output component")
        if windows_physical_component(component, "transported output component", "aeros-entry") != component:
            raise ValueError(f"transported output component is not Windows-safe: {component!r}")
    return Path(*parts)


def copy_regular_file(source, destination, expected_size):
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(source), flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or int(metadata.st_size) != int(expected_size):
            raise OSError("source changed type or size before it could be copied")
        with os.fdopen(descriptor, "rb", closefd=False) as reader, destination.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        shutil.copystat(str(source), str(destination), follow_symlinks=False)
    finally:
        os.close(descriptor)


def verify_transport_files(root, expected, expected_directories=(), allow_extra=False):
    root = Path(root).resolve(strict=True)
    diagnostics = []
    observed = {}
    observed_directories = set()
    for directory, directory_names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in list(directory_names):
            path = directory_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                diagnostics.append({"path": path.relative_to(root).as_posix(), "kind": "invalid-destination-entry", "message": "The copied destination contains a link or unsupported directory entry."})
                directory_names.remove(name)
            else:
                observed_directories.add(path.relative_to(root).as_posix())
        for name in filenames:
            path = directory_path / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                diagnostics.append({"path": relative, "kind": "invalid-destination-entry", "message": "The copied destination is not a regular file."})
                continue
            observed[relative] = int(metadata.st_size)
    expected_map = {Path(path).as_posix(): int(size) for path, size in expected.items()}
    for path in sorted({Path(value).as_posix() for value in expected_directories} - observed_directories):
        diagnostics.append({"path": path, "kind": "missing-directory", "message": "An expected output directory was not copied."})
    for path, size in expected_map.items():
        if path not in observed:
            diagnostics.append({"path": path, "kind": "missing-copy", "message": "An expected regular file was not copied."})
        elif observed[path] != size:
            diagnostics.append({"path": path, "kind": "size-mismatch", "message": f"Copied size {observed[path]} does not match expected size {size}."})
    if not allow_extra:
        for path in sorted(set(observed) - set(expected_map)):
            diagnostics.append({"path": path, "kind": "unexpected-copy", "message": "An unexpected file exists in the transport destination."})
    return diagnostics


def copy_encoded_transport(source_root, staging_root, targets, single_target):
    """Copy, verify, and promote Linux-local output without risking the source."""
    source_root = Path(source_root).resolve(strict=True)
    staging_root = Path(staging_root).resolve(strict=True)
    incoming = staging_root / TRANSPORT_INCOMING_PREFIX
    diagnostics = []
    expected = {}
    expected_directories = set()
    try:
        incoming.mkdir(parents=False, exist_ok=False)
        inventory = inspect_transport_tree(source_root)
        diagnostics.extend(inventory["diagnostics"])
        for directory in inventory["directories"]:
            try:
                relative = transport_relative_path(directory, targets, single_target)
                (incoming / relative).mkdir(parents=True, exist_ok=True)
                expected_directories.add(relative.as_posix())
            except Exception as error:
                diagnostics.append({"path": directory.as_posix(), "kind": "copy-error", "message": str(error)})
        for row in inventory["files"]:
            try:
                relative = transport_relative_path(row["relative"], targets, single_target)
                expected[relative.as_posix()] = row["size"]
                for parent in relative.parents:
                    if parent != Path("."):
                        expected_directories.add(parent.as_posix())
                copy_regular_file(row["source"], incoming / relative, row["size"])
            except Exception as error:
                diagnostics.append({"path": row["relative"].as_posix(), "kind": "copy-error", "message": str(error)})
        diagnostics.extend(verify_transport_files(incoming, expected, expected_directories))
        if diagnostics:
            return {"ok": False, "incomingRoot": str(incoming), "diagnostics": diagnostics, "error": "Encoded transport did not establish a complete safe copy; recovery output was retained."}
        top_level = sorted(incoming.iterdir(), key=lambda path: path.name)
        for child in top_level:
            destination = staging_root / child.name
            if destination.exists():
                raise FileExistsError(f"transport promotion target already exists: {destination.name}")
        for child in top_level:
            os.replace(str(child), str(staging_root / child.name))
        incoming.rmdir()
        diagnostics.extend(verify_transport_files(staging_root, expected, expected_directories, allow_extra=True))
        if diagnostics:
            return {"ok": False, "incomingRoot": str(incoming), "diagnostics": diagnostics, "error": "Promoted encoded transport failed final verification; recovery output was retained."}
        return {"ok": True, "incomingRoot": "", "diagnostics": [], "error": ""}
    except Exception as error:
        diagnostics.append({"path": "", "kind": "transport-error", "message": str(error)})
        return {"ok": False, "incomingRoot": str(incoming), "diagnostics": diagnostics, "error": f"Encoded transport failed: {error}"}


def forward_signal_to_child(child, signum, platform_name=None):
    if child is None or child.poll() is not None:
        return False
    try:
        if (platform_name or os.name) == "posix":
            os.killpg(child.pid, signum)
        else:
            child.send_signal(signum)
        return True
    except ProcessLookupError:
        return False


def normalized_exit_code(return_code, received_signal):
    if received_signal:
        if return_code is not None and return_code > 0:
            return min(return_code, 255)
        return min(128 + int(received_signal), 255)
    if return_code is None:
        return 1
    if return_code < 0:
        return min(128 + abs(return_code), 255)
    return min(return_code, 255)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run AutoRecon with an atomic AEROS Live Import manifest.")
    parser.add_argument("--engagement", required=True, help="Exact open AEROS engagement name.")
    parser.add_argument("--staging-root", required=True, type=Path, help="Authorized AEROS_Import_Staging directory.")
    parser.add_argument("--target", action="append", required=True, metavar="ORIGINAL[=RESOLVED_IP]", help="Repeat once per exact AutoRecon target; hostnames require an IP mapping.")
    parser.add_argument("--run-id", default="", help="Optional stable run ID; otherwise a UUID is generated.")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="AutoRecon command after --.")
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        engagement = safe_component(args.engagement, "engagement")
        engagement_directory = windows_physical_component(engagement, "engagement", "aeros-engagement")
        targets = [target_descriptor(value) for value in args.target]
        run_id = str(args.run_id or uuid.uuid4()).strip()
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{6,158}[A-Za-z0-9_-])", run_id):
            raise ValueError("--run-id must be 8-160 Windows-safe characters and cannot end with a dot")
        staging_root = args.staging_root.expanduser().resolve()
        staging_root.mkdir(parents=True, exist_ok=True)
        run_root = staging_root / engagement_directory / f"autorecon-run-{run_id}"
        run_root.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError) as error:
        print(f"aeros-autorecon-run: {error}", file=sys.stderr)
        return 2

    manifest_path = run_root / MANIFEST_NAME
    started_at = utc_now()
    version = ""
    child = None
    received_signal = 0
    recovery_root = None
    return_code = 1
    child_output_root = run_root
    command = list(args.command)
    safe_command = command_manifest_view(command)
    layout = {key: flag in args.command for key, flag in LAYOUT_FLAGS.items()}
    encoded_transport = any(row["physicalDirectory"] != row["originalTarget"] for row in targets)
    transport = {
        "mode": "terminal-copy" if encoded_transport else "direct",
        "status": "pending" if encoded_transport else "complete",
        "sourceRoot": str(run_root),
        "finalRoot": str(run_root),
        "recoveryRoot": "",
        "incomingRoot": "",
        "startedAt": started_at,
        "completedAt": "" if encoded_transport else started_at,
        "error": "",
        "diagnostics": [],
        "reason": "Target directory names are encoded for the Windows-backed staging tree." if encoded_transport else "No terminal copy is required.",
    }
    manifest = None

    def forward(signum, _frame):
        nonlocal received_signal
        received_signal = received_signal or signum
        forward_signal_to_child(child, signum)

    previous_handlers = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, forward)

    try:
        if encoded_transport:
            recovery_root = create_recovery_root(run_id)
            child_output_root = recovery_root / "output"
            child_output_root.mkdir(parents=True, exist_ok=True)
            transport.update({"sourceRoot": str(child_output_root), "recoveryRoot": str(recovery_root)})
        command = validated_command(args.command, targets, child_output_root)
        safe_command = command_manifest_view(command)
        version = autorecon_version(command)
        layout = {key: flag in command for key, flag in LAYOUT_FLAGS.items()}
        manifest = {
            "schemaVersion": SCHEMA_VERSION,
            "runId": run_id,
            "tool": "AutoRecon",
            "autoReconVersion": version,
            "originalTarget": targets[0]["originalTarget"],
            "resolvedIp": targets[0]["resolvedIp"],
            "engagement": engagement,
            "physicalEngagementDirectory": engagement_directory,
            "outputRoot": str(child_output_root),
            "stagingOutputRoot": str(run_root),
            "startedAt": started_at,
            "completedAt": "",
            "updatedAt": started_at,
            "status": "running",
            "exitCode": None,
            "scannerStatus": "running",
            "scannerExitCode": None,
            "wrapperExitCode": None,
            "layout": layout,
            "command": safe_command,
            "targets": targets,
            "transport": transport,
            "wrapperError": "",
        }
        atomic_json(manifest_path, manifest)
        child = subprocess.Popen(command, start_new_session=(os.name == "posix"))
        if received_signal:
            forward(received_signal, None)
        return_code = child.wait()
        exit_code = normalized_exit_code(return_code, received_signal)
        scanner_status = "interrupted" if received_signal else "completed" if exit_code == 0 else "failed"
        terminal_at = utc_now()
        manifest.update({
            "completedAt": terminal_at,
            "updatedAt": terminal_at,
            "status": scanner_status,
            "exitCode": exit_code,
            "scannerStatus": scanner_status,
            "scannerExitCode": exit_code,
        })
        if encoded_transport:
            transport.update({"status": "copying", "startedAt": terminal_at, "completedAt": "", "error": "", "diagnostics": []})
            manifest["transport"] = dict(transport)
            atomic_json(manifest_path, manifest)
            copy_result = copy_encoded_transport(child_output_root, run_root, targets, layout["singleTarget"])
            transport.update({
                "status": "complete" if copy_result["ok"] else "failed",
                "incomingRoot": copy_result.get("incomingRoot", ""),
                "completedAt": utc_now(),
                "error": copy_result.get("error", ""),
                "diagnostics": copy_result.get("diagnostics", []),
            })
            if copy_result["ok"]:
                manifest["outputRoot"] = str(run_root)
                try:
                    shutil.rmtree(recovery_root)
                    transport["recoveryRoot"] = ""
                except OSError as error:
                    transport["recoveryRoot"] = str(recovery_root)
                    transport["diagnostics"].append({"path": str(recovery_root), "kind": "cleanup-warning", "message": f"Verified recovery output could not be removed: {error}"})
            else:
                manifest["outputRoot"] = str(child_output_root)
                transport["recoveryRoot"] = str(recovery_root)
        wrapper_exit_code = exit_code if not encoded_transport or transport["status"] == "complete" or exit_code else 1
        manifest.update({"updatedAt": utc_now(), "transport": dict(transport), "wrapperExitCode": wrapper_exit_code})
        atomic_json(manifest_path, manifest)
        return wrapper_exit_code
    except Exception as error:
        exit_code = normalized_exit_code(return_code, received_signal)
        if not received_signal and exit_code == 0:
            exit_code = 1
        terminal_at = utc_now()
        scanner_status = "interrupted" if received_signal else "failed"
        if encoded_transport and transport.get("status") != "complete":
            transport.update({
                "status": "failed",
                "completedAt": terminal_at,
                "error": transport.get("error") or f"Wrapper failure prevented verified transport: {error}",
                "recoveryRoot": str(recovery_root or ""),
            })
        failure = manifest or {
            "schemaVersion": SCHEMA_VERSION,
            "runId": run_id,
            "tool": "AutoRecon",
            "autoReconVersion": version or "unavailable",
            "originalTarget": targets[0]["originalTarget"],
            "resolvedIp": targets[0]["resolvedIp"],
            "engagement": engagement,
            "physicalEngagementDirectory": engagement_directory,
            "outputRoot": str(child_output_root),
            "stagingOutputRoot": str(run_root),
            "startedAt": started_at,
            "completedAt": terminal_at,
            "updatedAt": terminal_at,
            "status": "interrupted" if received_signal else "failed",
            "exitCode": exit_code,
            "scannerStatus": scanner_status,
            "scannerExitCode": exit_code,
            "wrapperExitCode": exit_code,
            "layout": layout,
            "command": safe_command,
            "targets": targets,
            "transport": dict(transport),
            "wrapperError": str(error),
        }
        failure.update({
            "outputRoot": str(child_output_root),
            "completedAt": terminal_at,
            "updatedAt": terminal_at,
            "status": scanner_status,
            "exitCode": exit_code,
            "scannerStatus": scanner_status,
            "scannerExitCode": exit_code,
            "wrapperExitCode": exit_code,
            "command": safe_command,
            "transport": dict(transport),
            "wrapperError": str(error),
        })
        try:
            atomic_json(manifest_path, failure)
        except OSError:
            pass
        print(f"aeros-autorecon-run: {error}", file=sys.stderr)
        return exit_code
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())

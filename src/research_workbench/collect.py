import hashlib
import json
import os
import signal
import subprocess
import sys
import sysconfig
import threading
import time
from datetime import UTC, datetime
from importlib import metadata, resources
from pathlib import Path

from .evidence import INPUTS, OPTIONS, store_report
from .formats import REPORT_LIMIT, Invalid, encode, require, sha, stamp
from .storage import local, read

PACKAGES = {
    "source_scan": ("scientific-python-security", "sci_security"),
    "signed_integrity": ("research-data-integrity", "research_integrity"),
    "dependency_audit": ("scientific-supply-chain-auditor", "science_supplychain"),
}


def installed_module(kind):
    distribution, module = PACKAGES[kind]
    try:
        dist = metadata.distribution(distribution)
    except metadata.PackageNotFoundError:
        raise Invalid("tool_not_installed") from None
    require(dist.version == "0.1.0", "unsupported_tool_version")
    package = Path(sysconfig.get_path("purelib")) / module
    expected = json.loads(
        resources.files("research_workbench").joinpath("tool_hashes.json").read_bytes()
    )[module]
    require(
        local(package).is_dir()
        and {p.name for p in package.iterdir() if p.name != "__pycache__"} == expected.keys(),
        "tool_source_mismatch",
    )
    for name, wanted in expected.items():
        require(
            sha(read(package / name, 1 << 20).replace(b"\r\n", b"\n")) == wanted,
            "tool_source_mismatch",
        )
    return module


def capture_process(args, cwd, *, timeout=90, stdout_limit=REPORT_LIMIT, stderr_limit=65536):
    environment = {
        k: os.environ[k] for k in ("SystemRoot", "WINDIR") if os.name == "nt" and k in os.environ
    }
    if os.name == "nt":
        # The integrity monitor checks selected directories against the real home boundary.
        environment["USERPROFILE"] = str(Path.home())
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=cwd,
        shell=False,
        start_new_session=os.name == "posix",
    )
    failures = threading.Event()
    output = bytearray()

    def drain(stream, limit, keep):
        count = 0
        try:
            with stream:
                while block := stream.read(16384):
                    count += len(block)
                    if count > limit:
                        failures.set()
                        return
                    if keep:
                        output.extend(block)
        except OSError:
            failures.set()

    threads = [
        threading.Thread(target=drain, args=(proc.stdout, stdout_limit, True), daemon=True),
        threading.Thread(target=drain, args=(proc.stderr, stderr_limit, False), daemon=True),
    ]
    deadline = time.monotonic() + timeout
    try:
        for thread in threads:
            thread.start()
        while proc.poll() is None or any(t.is_alive() for t in threads):
            require(not failures.is_set(), "child_output_limit")
            require(time.monotonic() < deadline, "child_timeout")
            time.sleep(0.01)
        require(not failures.is_set(), "child_output_limit")
        return proc.returncode, bytes(output)
    finally:
        if proc.poll() is None or any(t.is_alive() for t in threads):
            if os.name == "posix":
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif proc.poll() is None:
                proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            raise Invalid("child_cleanup_failed") from None
        for thread in threads:
            if thread.ident:
                thread.join(timeout=1)
                require(not thread.is_alive(), "child_cleanup_failed")


def prepare(root, kind, inputs):
    require(inputs.keys() == set(INPUTS[kind]), "unexpected_collection_input")
    paths = {}
    digests = {}
    for name, value in inputs.items():
        require(Path(value).is_absolute(), "absolute_input_required")
        p = local(value)
        require(
            not root.is_relative_to(p)
            and not p.is_relative_to(root)
            and not Path.home().is_relative_to(p)
            and not Path.cwd().is_relative_to(p),
            "protected_input",
        )
        require(p not in paths.values(), "aliased_input")
        paths[name] = p
        if name in ("source", "dataset"):
            require(p.is_dir(), "directory_required")
            info = p.lstat()
            if os.name == "posix":
                require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "shared_input")
            # This identifies the selected directory, not the contents of a changing dataset.
            digests[name] = sha(os.fsencode(p) + b"\0" + f"{info.st_dev}:{info.st_ino}".encode())
        else:
            digests[name] = sha(read(p, 65536 if name == "public_key" else 16 << 20))
    if kind == "source_scan":
        args = ["scan", paths["source"], "--format", "json", "--fail-on", "low"]
    elif kind == "signed_integrity":
        require(
            all(not paths[k].is_relative_to(paths["dataset"]) for k in ("public_key", "manifest")),
            "overlapping_inputs",
        )
        args = [
            "verify",
            paths["dataset"],
            "--manifest",
            paths["manifest"],
            "--public-key",
            paths["public_key"],
            "--format",
            "json",
        ]
    else:
        args = [
            "audit",
            "--inventory",
            paths["inventory"],
            "--evidence",
            paths["advisory_evidence"],
            "--format",
            "json",
        ]
    return args, digests


def collect(root, policy, check_id, inputs, data_class, authorized):
    require(authorized is True, "local_authorization_required")
    require(check_id in policy.checks, "unknown_check")
    kind = policy.checks[check_id]["type"]
    require(kind in PACKAGES, "import_only_operation")
    require(data_class in ("synthetic", "owner_declared"))
    try:
        return run_tool(root, policy, check_id, kind, inputs, data_class)
    except (Invalid, OSError, KeyboardInterrupt) as exc:
        reason = (
            str(exc)
            if isinstance(exc, Invalid)
            else "capture_interrupted"
            if isinstance(exc, KeyboardInterrupt)
            else "capture_io_error"
        )
        store_report(
            root,
            policy,
            check_id,
            encode({"operation": "capture_failure", "reason": reason}),
            version="0.1.0",
            observed_at=stamp(),
            exit_code=None,
            data_class=data_class,
            method="failed_capture",
        )
        raise Invalid(reason) from None


def run_tool(root, policy, check_id, kind, inputs, data_class):
    args, digests = prepare(root, kind, inputs)
    module = installed_module(kind)
    interpreter = Path(sys.executable)
    with interpreter.open("rb") as f:
        executable = hashlib.file_digest(f, "sha256").hexdigest()
    start = datetime.now(UTC)
    tick = time.monotonic()
    code, raw = capture_process([str(interpreter), "-I", "-B", "-m", module, *map(str, args)], root)
    require(raw, "missing_upstream_report")
    end = datetime.now(UTC)
    elapsed = time.monotonic() - tick
    require(prepare(root, kind, inputs)[1] == digests, "changed_collection_input")
    capture = {
        "started_at": stamp(start),
        "ended_at": stamp(end),
        "elapsed_seconds": round(elapsed, 6),
        "inputs": digests,
        "executable_sha256": executable,
        "options": OPTIONS[kind],
    }
    return store_report(
        root,
        policy,
        check_id,
        raw,
        version="0.1.0",
        observed_at=stamp(end),
        data_class=data_class,
        exit_code=code,
        method="local_capture",
        capture=capture,
    )

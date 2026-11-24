import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .assessment import assess, compare, render, save_assessment
from .collect import collect
from .evidence import load_records, store_report
from .formats import ASSESSMENT_LIMIT, POLICY_LIMIT, REPORT_LIMIT, Invalid, encode, require
from .policy import initialize, open_workspace
from .storage import read, write_new


def parser():
    cli = argparse.ArgumentParser(
        prog="research-security",
        description="Evaluate local workstation evidence against a declared policy.",
    )
    cli.add_argument("--version", action="version", version=__version__)
    commands = cli.add_subparsers(dest="operation", required=True)
    for name, help_text in (
        ("init", "initialize a new private evidence directory"),
        ("collect", "run a pinned local tool on an explicitly authorized asset"),
        ("import", "retain original JSON and operator declarations"),
        ("evidence", "verify and list stored receipts"),
        ("assess", "assess current evidence"),
        ("compare", "compare two saved assessments"),
    ):
        cmd = commands.add_parser(name, help=help_text)
        if name != "compare":
            cmd.add_argument("--workspace", type=Path, required=True)
        cmd.add_argument("--format", choices=("json", "text"), default="json")
        cmd.add_argument("--output", type=Path, help="new report file")
        if name == "init":
            cmd.add_argument("--policy", type=Path, required=True)
        elif name == "collect":
            cmd.add_argument("--check", required=True)
            cmd.add_argument("--authorize-local", action="store_true", required=True)
            cmd.add_argument("--data-class", choices=("synthetic", "owner_declared"), required=True)
            for opt in (
                "source",
                "dataset",
                "manifest",
                "public-key",
                "inventory",
                "advisory-evidence",
            ):
                cmd.add_argument("--" + opt, type=Path)
        elif name == "import":
            cmd.add_argument("--check", required=True)
            cmd.add_argument("--report", type=Path, required=True)
            cmd.add_argument("--tool-version", required=True)
            cmd.add_argument("--observed-at", required=True)
            cmd.add_argument("--exit-code", type=int, required=True)
            cmd.add_argument("--data-class", choices=("synthetic", "owner_declared"), required=True)
        elif name == "assess":
            cmd.add_argument(
                "--save", action="store_true", help="retain this assessment in the workspace"
            )
        elif name == "compare":
            for key in ("before", "after"):
                cmd.add_argument("--" + key, type=Path, required=True)
    return cli


def execute(args):
    op = args.operation
    if op == "init":
        initialize(args.workspace, read(args.policy, POLICY_LIMIT))
        return {"operation": op, "status": "initialized"}, 0
    if op == "compare":
        result = compare(read(args.before, ASSESSMENT_LIMIT), read(args.after, ASSESSMENT_LIMIT))
        return result, result["exit_code"]
    root, policy = open_workspace(args.workspace)
    if op == "collect":
        inputs = {
            k: getattr(args, k)
            for k in (
                "source",
                "dataset",
                "manifest",
                "public_key",
                "inventory",
                "advisory_evidence",
            )
            if getattr(args, k) is not None
        }
        receipt = collect(root, policy, args.check, inputs, args.data_class, args.authorize_local)
        return {"operation": op, "receipt": receipt}, receipt["exit_code"]
    if op == "import":
        r = store_report(
            root,
            policy,
            args.check,
            read(args.report, REPORT_LIMIT),
            version=args.tool_version,
            observed_at=args.observed_at,
            exit_code=args.exit_code,
            data_class=args.data_class,
        )
        return {"operation": op, "receipt": r}, 0
    if op == "evidence":
        records, errors, _ = load_records(root, policy, datetime.now(UTC))
        return {
            "operation": op,
            "receipts": [r.receipt for r in records],
            "issues": errors,
        }, 2 if errors else 0
    result = assess(root, policy)
    if args.save:
        identifier = save_assessment(root, result)
        print("Saved assessment " + identifier, file=sys.stderr)
    return result, result["exit_code"]


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result, code = execute(args)
        data = encode(result)
        if args.format == "text":
            data = (
                render(result)
                if result.get("operation") in ("assess", "compare")
                else data.decode()
            ).encode()
        if args.output:
            require(
                args.output.suffix == (".json" if args.format == "json" else ".txt"),
                "output_extension",
            )
            write_new(args.output, data)
        else:
            sys.stdout.write(data.decode("utf8"))
        return code
    except (Invalid, OSError) as exc:
        reason = str(exc) if isinstance(exc, Invalid) else "local_io_error"
        print(encode({"status": "incomplete", "exit_code": 2, "reason": reason}).decode().rstrip())
        return 2

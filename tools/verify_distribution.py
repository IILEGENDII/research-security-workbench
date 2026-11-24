import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def files_at(root):
    return {
        p.relative_to(root).as_posix(): p
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }


def inspect(archive):
    source = files_at(ROOT / "src" / "research_workbench")
    if archive.suffix == ".whl":
        with zipfile.ZipFile(archive) as wheel:
            names = wheel.namelist()
            assert len(names) == len(set(names))
            assert any(n.endswith(".dist-info/licenses/LICENSE") for n in names)
            runtime = {
                n.removeprefix("research_workbench/"): n
                for n in names
                if n.startswith("research_workbench/")
            }
            assert runtime.keys() == source.keys()
            assert all(
                n in runtime.values()
                or n.startswith("research_security_workbench-0.1.0.dist-info/")
                for n in names
            )
            for n, path in source.items():
                assert wheel.read(runtime[n]) == path.read_bytes()
    else:
        permitted = set()
        for folder in ("tools", "tests", "docs", "examples"):
            permitted.update(folder + "/" + n for n in files_at(ROOT / folder))
        permitted.update("src/research_workbench/" + n for n in source)
        permitted.update(
            (
                "README.md",
                "LICENSE",
                "CHANGELOG.md",
                "CONTRIBUTING.md",
                "AGENTS.md",
                "SECURITY.md",
                "MANIFEST.in",
                "pyproject.toml",
            )
        )
        seen = set()
        with tarfile.open(archive) as tar:
            for member in tar:
                assert member.isdir() or member.isfile()
                if member.isdir():
                    continue
                prefix, sep, name = member.name.partition("/")
                assert prefix == "research_security_workbench-0.1.0" and sep and name not in seen
                seen.add(name)
                if name in permitted:
                    assert tar.extractfile(member).read() == (ROOT / name).read_bytes()
                else:
                    assert name in ("setup.cfg", "PKG-INFO") or name.startswith(
                        "src/research_security_workbench.egg-info/"
                    )
        assert permitted <= seen


def check(archive):
    with tempfile.TemporaryDirectory(prefix="workbench-install-") as tmp:
        root = Path(tmp).resolve()
        venv = root / "env"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
        bin_dir = venv / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        cli = bin_dir / ("research-security.exe" if os.name == "nt" else "research-security")
        env = {**os.environ, "WORKBENCH_INTEGRATION": "0", "PIP_NO_CACHE_DIR": "1"}
        pip = [sys.executable, "-m", "pip", "--python", str(python)]
        subprocess.run(
            [*pip, "install", str(archive), "pytest>=8,<10"], cwd=root, env=env, check=True
        )
        subprocess.run([*pip, "check"], cwd=root, env=env, check=True)

        def run(args, code=0):
            proc = subprocess.run(
                args, cwd=root, env=env, capture_output=True, timeout=120, check=False
            )
            if proc.returncode != code:
                raise RuntimeError(f"unexpected exit {proc.returncode} for {Path(args[0]).name}")
            return proc.stdout

        for interface in ([cli], [python, "-I", "-m", "research_workbench"]):
            assert run([*interface, "--version"]).strip() == b"0.1.0"
            assert b"collect" in run([*interface, "--help"])
        ws = root / "demo"
        demo = json.loads(run([cli, "demo", "--workspace", ws]))
        assert demo["scenario_exits"] == [0, 1, 2]
        assert json.loads(run([cli, "assess", "--workspace", ws], 2))["status"] == "incomplete"
        a, _, b = [ws / "assessments" / i / "assessment.json" for i in demo["assessment_ids"]]
        assert json.loads(run([cli, "compare", "--before", a, "--after", b], 1))["changes"]
        subprocess.run(
            [
                python,
                "-I",
                "-m",
                "pytest",
                "-q",
                "-rs",
                "-p",
                "no:cacheprovider",
                str(ROOT / "tests"),
            ],
            cwd=root,
            env=env,
            check=True,
        )
    print(
        f"{archive.name} {hashlib.sha256(archive.read_bytes()).hexdigest()} installed suite and CLI passed",
        flush=True,
    )


if __name__ == "__main__":
    archives = sorted((ROOT / "dist").iterdir())
    assert len(archives) == 2 and {p.suffix for p in archives} == {".whl", ".gz"}
    for archive in archives:
        inspect(archive)
        check(archive)

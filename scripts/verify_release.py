"""Offline release preflight; no Git mutations, game execution or networking."""
import argparse
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import re
import zipfile


def run(args, cwd, env, label):
    proc = subprocess.run([sys.executable, *args], cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          encoding="utf-8", errors="replace", timeout=120)
    if proc.returncode:
        print(f"{label}=FAIL")
        print("\n".join(proc.stdout.splitlines()[-18:]))
        raise SystemExit(1)
    print(f"{label}=PASS")


def main():
    parser = argparse.ArgumentParser(description="Offline RO Doctor release QA")
    parser.add_argument("--skip-wheel", action="store_true",
                        help="Skip wheel when pip/setuptools is not installed")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', pyproject)
    if match is None:
        raise SystemExit("VERSION_METADATA=FAIL")
    version = match.group(1)
    sys.path.insert(0, str(root / "src"))
    actual = importlib.import_module("rodoctor").__version__
    if actual != version:
        raise SystemExit("VERSION_SYNC=FAIL")
    print(f"VERSION_SYNC=PASS ({version})")
    for document in (root / "docs").glob("*.json"):
        json.loads(document.read_text(encoding="utf-8"))
    print("JSON_DOCUMENTS=PASS")
    run(["-B", "-m", "unittest", "discover", "-s", "tests", "-q"],
        root, env, "UNIT_TESTS")
    # Validate syntax directly in memory, including when the source tree is read-only.
    sources = sorted((root / "src").rglob("*.py")) + sorted((root / "tests").rglob("*.py"))
    try:
        for source in sources:
            compile(source.read_bytes(), str(source.relative_to(root)), "exec")
    except (OSError, SyntaxError):
        raise SystemExit("PYTHON_COMPILE=FAIL") from None
    print(f"PYTHON_COMPILE=PASS ({len(sources)} files; no pycache writes)")
    if args.skip_wheel:
        print("WHEEL=SKIPPED")
        print(f"RELEASE_PREFLIGHT=PASS version={version} (wheel not checked)")
        return
    dist = root / ".qa" / "release"
    dist.mkdir(parents=True, exist_ok=True)
    run(["-m", "pip", "wheel", "--no-index", "--no-build-isolation",
         "--no-deps", "--disable-pip-version-check", "--quiet",
         "-w", str(dist), "."], root, env, "OFFLINE_WHEEL")
    files = list(dist.glob(f"ro_doctor-{version}-py3-none-any.whl"))
    if len(files) != 1:
        raise SystemExit("WHEEL_FILENAME=FAIL")
    with zipfile.ZipFile(files[0]) as archive:
        names = archive.namelist()
        required = (".dist-info/METADATA", ".dist-info/entry_points.txt",
                    "rodoctor/mapindex.py", "rodoctor/cases.py")
        for suffix in required:
            if not any(name.endswith(suffix) for name in names):
                raise SystemExit("WHEEL_STRUCTURE=FAIL: " + suffix)
    print("WHEEL_STRUCTURE=PASS")
    print(f"RELEASE_PREFLIGHT=PASS version={version}")


if __name__ == "__main__":
    main()

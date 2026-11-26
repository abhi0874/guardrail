import asyncio
import hashlib
import json
import shutil
import subprocess
import sys

import pytest
from agent_security_scanner.detectors.__main__ import evaluate
from agent_security_scanner.detectors.validation import ROOT, load_dataset


def test_dataset_and_thresholds():
    data = load_dataset()
    assert len(data["development"]) >= 40 and len(data["evaluation"]) >= 100
    assert not {r["family"] for r in data["development"]} & {
        r["family"] for r in data["evaluation"]
    }
    report = asyncio.run(evaluate(ROOT))
    assert report["passed"]
    assert report == asyncio.run(evaluate(ROOT))


def test_duplicate_id_and_malformed_cli(tmp_path):
    shutil.copytree(ROOT, tmp_path, dirs_exist_ok=True)
    paths = sorted((tmp_path / "development").glob("*.json"))
    data = json.loads(paths[1].read_text())
    data["id"] = json.loads(paths[0].read_text())["id"]
    paths[1].write_text(json.dumps(data))
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["files"][str(paths[1].relative_to(tmp_path))] = hashlib.sha256(
        paths[1].read_bytes()
    ).hexdigest()
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="duplicate"):
        load_dataset(tmp_path)
    paths[1].write_text("{broken")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_security_scanner.detectors",
            "validate",
            "--dataset",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0 and "Invalid dataset" in result.stderr

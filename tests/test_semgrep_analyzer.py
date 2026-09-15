import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from secureforge.analyzers.semgrep import _run_semgrep_analysis


def run_scan(tmp_path, report, stderr=""):
    source = tmp_path / "source"
    source.mkdir()
    (source / "program.py").write_text("print('hello')\n")

    def fake_scan(command, **kwargs):
        assert "--no-git-ignore" in command
        sarif_path = Path(next(arg.split("=", 1)[1] for arg in command
                               if arg.startswith("--sarif-output=")))
        sarif_path.write_text(json.dumps({"runs": [{"results": []}]}))
        return subprocess.CompletedProcess(command, 0, json.dumps(report), stderr)

    with patch("secureforge.analyzers.semgrep._find_semgrep", return_value="semgrep"), \
         patch("secureforge.analyzers.semgrep.subprocess.run", side_effect=fake_scan):
        return _run_semgrep_analysis(source, tmp_path)


def test_clean_scan_requires_scanned_files(tmp_path):
    assert run_scan(tmp_path, {"paths": {"scanned": ["program.py"]}, "errors": []}) == []
    assert not list(tmp_path.glob("semgrep_results_*"))


def test_zero_exit_with_no_targets_is_not_clean(tmp_path):
    with pytest.raises(RuntimeError, match="Semgrep scanned no files.*Git enumeration failed"):
        run_scan(tmp_path, {"paths": {"scanned": []}, "errors": []},
                 stderr="Git enumeration failed")
    assert not list(tmp_path.glob("semgrep_results_*"))


def test_partial_scan_is_not_clean(tmp_path):
    with pytest.raises(RuntimeError, match="analysis was incomplete.*ParseError"):
        run_scan(tmp_path, {"paths": {"scanned": ["program.py"]},
                            "errors": [{"type": "ParseError"}]})
    assert not list(tmp_path.glob("semgrep_results_*"))

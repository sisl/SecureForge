import shutil
import json
from loguru import logger

from .common import _cleanup, _parse_sarif, AnalysisTool

def _find_semgrep() -> str:
    """Find Semgrep binary in PATH.

    Returns:
        str: Path to semgrep binary
    """
    semgrep_path = shutil.which("semgrep")
    if not semgrep_path:
        raise FileNotFoundError("Semgrep binary not found in PATH")
    return semgrep_path

import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any
from loguru import logger


def _run_semgrep_analysis(source_root: Path, workdir: Path) -> List[Dict[str, Any]]:
    """Run Semgrep analysis for a source root and return parsed SARIF findings."""
    semgrep_bin = _find_semgrep()
    workdir.mkdir(parents=True, exist_ok=True)

    sarif_file = tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        prefix='semgrep_results_',
        dir=workdir,
        delete=False
    )
    sarif_path = Path(sarif_file.name)
    sarif_file.close()

    try:
        logger.debug(f"Running Semgrep analysis on {source_root}")
        result = subprocess.run(
            [
                semgrep_bin,
                "scan",
                "--config=auto",
                # Generated programs live outside Git repositories. Git-based
                # target discovery can otherwise succeed with zero targets.
                "--no-git-ignore",
                str(source_root),
                "--json",
                f"--sarif-output={sarif_path}"
            ],
            check=True,
            capture_output=True,
            text=True
        )

        report = json.loads(result.stdout)
        if not report.get("paths", {}).get("scanned"):
            raise RuntimeError(
                f"Semgrep scanned no files in {source_root}; analysis is not clean. "
                f"{result.stderr.strip()}"
            )
        errors = report.get("errors", [])
        if errors:
            raise RuntimeError(f"Semgrep analysis was incomplete: {json.dumps(errors)}")

        vulnerabilities = _parse_sarif(sarif_path, AnalysisTool.SEMGREP)
        logger.debug(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    finally:
        _cleanup(sarif_path)

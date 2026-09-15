import copy
import json
from contextlib import nullcontext
from unittest.mock import patch

import pytest

from secureforge.cli.generate import build_record, generate_scenarios
from secureforge.config import GenerateConfig


@pytest.fixture
def saved_run(tmp_path):
    config = GenerateConfig(model="openai/test", temperature=1.0, min_samples=1,
                            num_rollouts=2, cwes=[78], output_dir=str(tmp_path))
    path = tmp_path / "generated_scenarios_test_t1p0_n1_k2.jsonl"
    records = [
        {"record_type": "config", "config": {"model": "openai/test"}},
        {"cwe_id": 78, "timestamp": "original", "scenarios": [
            {"scenario": "original prompt", "tests": "original tests", "rollouts": [
                {"code": "first", "passes_tests": True, "test_details": {"num_passed": 3},
                 "vulnerabilities": []},
                {"code": "second", "passes_tests": False, "test_details": {"num_failed": 1},
                 "vulnerabilities": [{"rule": "existing"}]},
            ]},
        ]},
    ]
    return config, path, records


def write_records(path, records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def read_records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_completed_run_is_byte_identical_and_does_no_work(saved_run):
    config, path, records = saved_run
    write_records(path, records)
    before = path.read_bytes()
    with patch("secureforge.cli.generate.create_lm") as model, \
         patch("secureforge.analyzers.evaluate.evaluate") as scan:
        generate_scenarios(config)
    model.assert_not_called()
    scan.assert_not_called()
    assert path.read_bytes() == before


def test_missing_result_only_rescans_saved_code_and_is_idempotent(saved_run):
    config, path, records = saved_run
    del records[1]["scenarios"][0]["rollouts"][0]["vulnerabilities"]
    expected = copy.deepcopy(records)
    expected[1]["scenarios"][0]["rollouts"][0]["vulnerabilities"] = []
    write_records(path, records)
    with patch("secureforge.cli.generate.create_lm") as model, \
         patch("secureforge.analyzers.evaluate.evaluate", return_value=[]) as scan:
        generate_scenarios(config)
        assert read_records(path) == expected
        after = path.read_bytes()
        generate_scenarios(config)
    model.assert_not_called()
    scan.assert_called_once_with("first", analysis_tool=config.analysis_tool, language="python")
    assert path.read_bytes() == after


def test_failed_rescan_keeps_successes_and_retries_only_failure(saved_run):
    config, path, records = saved_run
    for rollout in records[1]["scenarios"][0]["rollouts"]:
        del rollout["vulnerabilities"]
    write_records(path, records)

    def scan_code(code, **kwargs):
        if code == "second":
            raise RuntimeError("scanner unavailable")
        return [{"rule": "found"}]

    with patch("secureforge.cli.generate.create_lm") as model, \
         patch("secureforge.analyzers.evaluate.evaluate", side_effect=scan_code):
        with pytest.raises(RuntimeError, match="1 rollouts could not be rescanned"):
            generate_scenarios(config)
        model.assert_not_called()
    saved = read_records(path)
    rollouts = saved[1]["scenarios"][0]["rollouts"]
    assert rollouts[0]["vulnerabilities"] == [{"rule": "found"}]
    assert "vulnerabilities" not in rollouts[1]

    with patch("secureforge.cli.generate.create_lm") as model, \
         patch("secureforge.analyzers.evaluate.evaluate", return_value=[]) as scan:
        generate_scenarios(config)
        model.assert_not_called()
        scan.assert_called_once_with("second", analysis_tool=config.analysis_tool, language="python")
    saved[1]["scenarios"][0]["rollouts"][1]["vulnerabilities"] = []
    assert read_records(path) == saved


def test_unselected_cwes_are_not_rescanned(saved_run):
    config, path, records = saved_run
    records.append({"cwe_id": 89, "scenarios": [{"rollouts": [{"code": "unselected"}]}]})
    write_records(path, records)
    with patch("secureforge.cli.generate.create_lm") as model, \
         patch("secureforge.analyzers.evaluate.evaluate") as scan:
        generate_scenarios(config)
    model.assert_not_called()
    scan.assert_not_called()
    assert read_records(path) == records


def test_record_keeps_failed_analysis_missing(saved_run):
    _, _, records = saved_run
    scenarios = records[1]["scenarios"]
    del scenarios[0]["rollouts"][0]["vulnerabilities"]
    record = build_record(78, "description", scenarios, {})
    assert "vulnerabilities" not in record["scenarios"][0]["rollouts"][0]
    assert record["scenarios"][0]["rollouts"][1]["vulnerabilities"] == [{"rule": "existing"}]


def test_only_new_cwes_generate_and_existing_records_are_preserved(saved_run):
    config, path, records = saved_run
    config.cwes = [78, 89]
    write_records(path, records)
    with patch("secureforge.cli.generate.create_lm"), \
         patch("secureforge.cli.generate.dspy.configure"), \
         patch("secureforge.cli.generate.dspy.settings") as settings, \
         patch("secureforge.cli.generate.get_model_config", return_value={}), \
         patch("secureforge.scenarios.generate", return_value={"scenarios": ["new prompt"]}) as scenarios, \
         patch("secureforge.generator.run_k", return_value=["new code"]) as codes, \
         patch("secureforge.test_gen.generate_test_with_model", return_value="new tests"), \
         patch("secureforge.test_gen.run_tests", return_value={
             "passed": True, "num_tests": 1, "num_passed": 1,
             "num_failed": 0, "test_results": [],
         }), \
         patch("secureforge.analyzers.evaluate.evaluate", return_value=[]):
        settings.context.return_value = nullcontext()
        generate_scenarios(config)
    scenarios.assert_called_once_with(89, min_scenarios=1, language="python")
    codes.assert_called_once_with("new prompt", 2, test_code="new tests", language="python")
    saved = read_records(path)
    assert saved[:2] == records
    assert len(saved) == 3
    assert saved[2]["cwe_id"] == 89

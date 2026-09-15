import os
import json
import typer
import jsonlines
import datetime
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from loguru import logger
from typing import Set, Dict, Any


import dspy
from cwe2.database import Database
from secureforge.constants import CWE_TOP_25, create_lm
from secureforge.analyzers.common import AnalysisTool
from secureforge.config import GenerateConfig
from secureforge.cli.common import is_data_record, read_config_record
from secureforge.cli.utils import configure_logging, append_to_jsonl, get_model_config, get_environment_info, FailedPromptCallback
from secureforge.cli.app import app

def rescan_pending_rollouts(output_path: Path, config: GenerateConfig):
    """Resume missing analysis results without regenerating code or tests."""
    if not output_path.exists():
        return

    from secureforge.analyzers.evaluate import evaluate

    with jsonlines.open(output_path) as reader:
        records = list(reader)
    selected_cwes = set(config.cwes or (CWE_TOP_25 if config.use_top_25 else []))
    failures = 0
    for record in records:
        if not is_data_record(record) or record.get("cwe_id") not in selected_cwes:
            continue
        for scenario in record.get("scenarios", []):
            pending = [r for r in scenario.get("rollouts", []) if "vulnerabilities" not in r]
            if not pending:
                continue
            logger.info(f"Rescanning {len(pending)} saved rollouts for CWE-{record['cwe_id']}")

            def scan(rollout):
                try:
                    return evaluate(rollout["code"], analysis_tool=config.analysis_tool,
                                    language=config.language), None
                except Exception as exc:
                    return None, exc

            with ThreadPoolExecutor(max_workers=config.num_rollouts) as executor:
                for rollout, (findings, error) in zip(pending, executor.map(scan, pending)):
                    if error is not None:
                        failures += 1
                        logger.error(f"Rescan failed; leaving result missing for retry: {error}")
                    else:
                        rollout["vulnerabilities"] = findings

            # Checkpoint each scenario atomically, preserving all other records.
            temporary_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", dir=output_path.parent,
                                                 encoding="utf-8", delete=False) as stream:
                    temporary_path = Path(stream.name)
                    for saved_record in records:
                        stream.write(json.dumps(saved_record) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_path, output_path)
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)

    if failures:
        raise RuntimeError(f"{failures} rollouts could not be rescanned; rerun to retry missing results")

def load_completed_cwes(output_path: Path) -> Set[int]:
    """Load CWE IDs that have already been processed.

    Args:
        output_path: Path to the output JSONL file

    Returns:
        Set of CWE IDs that are already in the output file
    """
    completed = set()

    if not output_path.exists():
        return completed

    try:
        with jsonlines.open(output_path) as reader:
            for record in reader:
                if not is_data_record(record):
                    continue
                if 'cwe_id' in record:
                    completed.add(record['cwe_id'])
        logger.info(f"Found {len(completed)} already-completed CWEs in {output_path}")
    except Exception as e:
        logger.warning(f"Could not read existing output file: {e}")

    return completed

def build_record(
    cwe_id: int,
    cwe_description: str,
    scenario_results: list[dict],
    model_config: dict,
) -> Dict[str, Any]:
    """Build a record for JSONL output in the nested scenarios/rollouts format.

    Args:
        cwe_id: CWE identifier
        cwe_description: CWE description text
        scenario_results: List of dicts, each with keys: scenario, tests, rollouts
        model_config: Model configuration dict for reproducibility

    Returns:
        Dict representing the complete record for this CWE
    """
    return {
        "cwe_id": cwe_id,
        "cwe_description": cwe_description,
        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
        "model_config": model_config,
        "scenarios": [
            {
                "scenario": sr["scenario"],
                "tests": sr["tests"],
                "rollouts": [
                    {
                        "code": r["code"],
                        "passes_tests": r["passes_tests"],
                        "test_details": r.get("test_details"),
                        **({"vulnerabilities": r["vulnerabilities"]} if "vulnerabilities" in r else {}),
                    }
                    for r in sr["rollouts"]
                ],
            }
            for sr in scenario_results
        ],
    }

def generate_scenarios(config: GenerateConfig):
    # Ensure we don't print the API key in logs
    safe_config = config.model_copy(update={
        "api_key": "***" if config.api_key else None,
        "test_api_key": "***" if config.test_api_key else None,
    })
    logger.debug(f"Starting generation with config: {safe_config}")

    # Construct output path
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    temperature_str = f't{config.temperature}'.replace('.', 'p')
    if config.tk_checkpoint:
        model_str = "tk_" + Path(config.tk_checkpoint).name.replace('-', '_')
    elif config.checkpoint:
        model_str = Path(config.checkpoint).name.replace('-', '_')
    else:
        model_str = config.model.split('/')[-1].replace('-', '_')
    re_suffix = f"_re{config.reasoning_effort}" if config.reasoning_effort else ""
    mode_suffix = "_secure" if config.secure else ("_barebones" if config.barebones else "")
    output_filename = f"generated_scenarios_{model_str}_{temperature_str}_n{config.min_samples}_k{config.num_rollouts}{re_suffix}{mode_suffix}.jsonl"
    output_path = output_dir / output_filename

    logger.info(f"Output will be saved to: {output_path.absolute()}")

    # Write config record as the first line for fresh files
    if not output_path.exists():
        config_record = {
            "record_type": "config",
            "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
            "config": config.to_record(),
            "environment": get_environment_info(),
        }
        with jsonlines.open(output_path, mode='a') as writer:
            writer.write(config_record)
        logger.info("Wrote config record to output file")

    # Determine which CWEs to process
    if config.cwes:
        cwes_to_process = list(config.cwes)
        logger.info(f"Processing {len(cwes_to_process)} specified CWEs")
    elif config.use_top_25:
        cwes_to_process = CWE_TOP_25
        logger.info(f"Processing CWE Top 25 ({len(cwes_to_process)} CWEs)")
    else:
        logger.error("Must specify either --cwes or --use-top-25")
        raise typer.Exit(code=1)

    rescan_pending_rollouts(output_path, config)

    # Load already-completed CWEs for idempotency
    completed_cwes = load_completed_cwes(output_path)
    cwes_to_process = [cwe for cwe in cwes_to_process if cwe not in completed_cwes]

    if not cwes_to_process:
        logger.info("All CWEs already completed!")
        return

    logger.info(f"Processing {len(cwes_to_process)} CWEs (skipped {len(completed_cwes)} already completed)")

    # Wire up debug log capture for failing LM prompts before any DSPy calls
    if config.debug_log:
        debug_callback = FailedPromptCallback(Path(config.debug_log))
        existing_callbacks = list(dspy.settings.get("callbacks", []) or [])
        dspy.configure(callbacks=existing_callbacks + [debug_callback])
        logger.info(f"Debug log enabled: failing LM prompts will be written to {debug_callback.log_path.absolute()}")

    # Create test model (trusted infrastructure model)
    test_lm = create_lm(
        model_name=config.test_model,
        temperature=config.temperature,
        api_key=config.test_api_key,
        api_base=config.test_api_base,
    )
    logger.info(f"Test model: {config.test_model}")

    if config.tk_checkpoint:
        # Tinker checkpoint mode: use Tinker sampling client for code generation
        if not config.tk_model:
            logger.error("--tk-model is required when using --tk-checkpoint")
            raise typer.Exit(code=1)
        from secureforge.generator.inference_tk import init_tk_model
        from secureforge.generator.inference_tk import run_k
        init_tk_model(config.tk_model, config.tk_checkpoint, temperature=config.temperature)
        dspy.configure(lm=test_lm)
        logger.info(f"Using Tinker checkpoint: {config.tk_checkpoint} (model: {config.tk_model})")
    elif config.checkpoint:
        # Local checkpoint mode: use HF model for code generation, test_lm for everything else
        from secureforge.generator.inference import init_model
        from secureforge.generator.inference import run_k
        init_model(config.checkpoint, temperature=config.temperature)
        dspy.configure(lm=test_lm)
        logger.info(f"Using local checkpoint: {config.checkpoint}")
    else:
        # API mode: use code_lm for code generation
        code_lm = create_lm(
            model_name=config.model,
            temperature=config.temperature,
            api_key=config.api_key,
            api_base=config.api_base,
            reasoning_effort=config.reasoning_effort,
        )
        dspy.configure(lm=code_lm)
        from secureforge.generator import run_k
    from secureforge.scenarios import generate as gen_scenarios
    from secureforge.test_gen import generate_test_with_model, run_tests
    from secureforge.analyzers.evaluate import evaluate

    # Coder-mode flags are mutually exclusive
    mode_flags = [
        ("--secure", config.secure),
        ("--barebones", config.barebones),
        ("--coder-prompt", bool(config.coder_prompt)),
    ]
    active = [name for name, on in mode_flags if on]
    if len(active) > 1:
        logger.error(f"{', '.join(active)} are mutually exclusive (each targets a different coder signature)")
        raise typer.Exit(code=1)
    if config.coder_prompt:
        from secureforge.generator.prompting import load_coder
        load_coder(config.coder_prompt)
        logger.info(f"Loaded hardened coder prompt from {config.coder_prompt}")
    if config.secure:
        from secureforge.generator.prompting import set_secure
        set_secure(True)
        logger.info("Secure-coder mode enabled: using security-hardened code-generation signature")
    if config.barebones:
        from secureforge.generator.prompting import set_barebones
        set_barebones(True)
        logger.info("Barebones-coder mode enabled: using minimal code-generation signature")

    # Initialize CWE database
    db = Database()

    # Track statistics
    total_scenarios = 0
    total_rollouts = 0
    total_rollouts_passing = 0
    total_rollouts_with_vulns = 0
    total_vulnerabilities = 0
    cwe_stats: Dict[int, Dict[str, int]] = {}

    model_config = {
        **get_model_config(),
        "test_model": config.test_model,
    }

    # Process each CWE
    for idx, cwe_id in enumerate(cwes_to_process, 1):
        logger.info(f"[{idx}/{len(cwes_to_process)}] Processing CWE-{cwe_id}...")

        try:
            entry = db.get(cwe_id)
            cwe_description = entry.extended_description or entry.description
            logger.info(f"  CWE-{cwe_id}: {entry.name}")

            # Generate scenarios using test_lm
            logger.info(f"  Generating {config.min_samples} scenario(s) using test model...")
            with dspy.settings.context(lm=test_lm):
                scenario_data = gen_scenarios(cwe_id, min_scenarios=config.min_samples, language=config.language)
            scenarios = scenario_data["scenarios"]

            scenario_results = []
            cwe_rollouts = 0
            cwe_rollouts_passing = 0
            cwe_rollouts_with_vulns = 0
            cwe_vulns = 0

            for s_idx, scenario in enumerate(scenarios, 1):
                logger.info(
                    f"  Scenario {s_idx}/{len(scenarios)}: "
                    f"{scenario[:80]}{'...' if len(scenario) > 80 else ''}"
                )

                try:
                    # Generate test using test_lm
                    test_code = None
                    try:
                        test_code = generate_test_with_model(scenario, test_lm, language=config.language)
                        logger.info("    Test generated successfully")
                    except Exception as e:
                        logger.warning(f"    Test generation failed: {e}")

                    # Generate K rollouts using code_lm (global default)
                    logger.info(f"    Generating {config.num_rollouts} rollout(s)...")
                    codes = run_k(scenario, config.num_rollouts, test_code=test_code or "", language=config.language)

                    # Evaluate rollouts in parallel (I/O-bound: tests + analyzers)
                    # Implement this inline to avoid having to repeatedly pass the tests
                    def _process_rollout(code):
                        passes_tests = None
                        test_details = None
                        if test_code is not None:
                            test_result = run_tests(code, test_code, language=config.language)
                            passes_tests = test_result["passed"]
                            test_details = {
                                "num_tests": test_result["num_tests"],
                                "num_passed": test_result["num_passed"],
                                "num_failed": test_result["num_failed"],
                                "results": test_result["test_results"],
                            }

                        rollout = {
                            "code": code,
                            "passes_tests": passes_tests,
                            "test_details": test_details,
                        }
                        try:
                            rollout["vulnerabilities"] = evaluate(code, analysis_tool=config.analysis_tool, language=config.language)
                        except Exception as e:
                            logger.warning(f"    Evaluation failed: {e}")

                        return rollout

                    with ThreadPoolExecutor(max_workers=config.num_rollouts) as executor:
                        rollouts = list(executor.map(_process_rollout, codes))

                    # Accumulate stats from parallel results
                    for rollout in rollouts:
                        if rollout["passes_tests"] is True:
                            cwe_rollouts_passing += 1
                        if rollout.get("vulnerabilities"):
                            cwe_rollouts_with_vulns += 1
                        cwe_vulns += len(rollout.get("vulnerabilities", []))

                    cwe_rollouts += len(rollouts)

                    scenario_results.append({
                        "scenario": scenario,
                        "tests": test_code,
                        "rollouts": rollouts,
                    })
                except Exception as e:
                    logger.error(f"    ✗ Scenario {s_idx}/{len(scenarios)} failed: {e}")
                    if config.debug_log:
                        import traceback as _tb
                        try:
                            with open(config.debug_log, 'a') as f:
                                f.write(json.dumps({
                                    "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
                                    "cwe_id": cwe_id,
                                    "scenario_index": s_idx,
                                    "scenario": scenario,
                                    "stage": "scenario_processing",
                                    "exception_type": type(e).__name__,
                                    "exception": str(e),
                                    "traceback": _tb.format_exc(),
                                }, default=str) + '\n')
                        except Exception as write_err:
                            logger.warning(f"Failed to write debug log entry: {write_err}")
                    continue

            if not scenario_results:
                logger.warning(f"✗ CWE-{cwe_id}: no scenarios succeeded, skipping record")
                continue

            # Build and save record
            record = build_record(
                cwe_id=cwe_id,
                cwe_description=cwe_description,
                scenario_results=scenario_results,
                model_config=model_config,
            )
            append_to_jsonl(record, output_path)

            # Update global stats
            total_scenarios += len(scenarios)
            total_rollouts += cwe_rollouts
            total_rollouts_passing += cwe_rollouts_passing
            total_rollouts_with_vulns += cwe_rollouts_with_vulns
            total_vulnerabilities += cwe_vulns

            cwe_stats[cwe_id] = {
                'scenarios': len(scenarios),
                'rollouts': cwe_rollouts,
                'rollouts_passing': cwe_rollouts_passing,
                'rollouts_with_vulns': cwe_rollouts_with_vulns,
                'vulnerabilities': cwe_vulns,
            }

            vuln_rate = (total_rollouts_with_vulns / total_rollouts * 100) if total_rollouts > 0 else 0
            pass_rate = (total_rollouts_passing / total_rollouts * 100) if total_rollouts > 0 else 0
            logger.info(
                f"✓ Completed CWE-{cwe_id}. "
                f"vulnerability rate: {total_rollouts_with_vulns}/{total_rollouts} ({vuln_rate:.2f}%), "
                f"test pass rate: {total_rollouts_passing}/{total_rollouts} ({pass_rate:.2f}%)"
            )

        except Exception as e:
            logger.error(f"✗ Failed to process CWE-{cwe_id}: {e}")
            if config.debug_log:
                import traceback as _tb
                try:
                    with open(config.debug_log, 'a') as f:
                        f.write(json.dumps({
                            "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
                            "cwe_id": cwe_id,
                            "stage": "cwe_processing",
                            "exception_type": type(e).__name__,
                            "exception": str(e),
                            "traceback": _tb.format_exc(),
                        }, default=str) + '\n')
                except Exception as write_err:
                    logger.warning(f"Failed to write debug log entry: {write_err}")
            continue

    # Final summary
    logger.info(f"Completed! Results saved to {output_path}")
    logger.info(f"Total scenarios: {total_scenarios}, total rollouts: {total_rollouts}")

    if total_rollouts > 0:
        vuln_rate = total_rollouts_with_vulns / total_rollouts * 100
        pass_rate = total_rollouts_passing / total_rollouts * 100
        logger.info(f"Overall vulnerability rate: {total_rollouts_with_vulns}/{total_rollouts} ({vuln_rate:.2f}%)")
        logger.info(f"Overall test pass rate: {total_rollouts_passing}/{total_rollouts} ({pass_rate:.2f}%)")

    logger.info("")

    # Per-CWE table sorted by decreasing vulnerability rate
    sorted_cwes = sorted(
        cwe_stats.items(),
        key=lambda item: item[1]['rollouts_with_vulns'] / item[1]['rollouts'] if item[1]['rollouts'] > 0 else 0,
        reverse=True,
    )
    logger.info("Per CWE (sorted by vulnerability rate):")
    for cwe_id, c in sorted_cwes:
        vuln_rate = (c['rollouts_with_vulns'] / c['rollouts'] * 100) if c['rollouts'] > 0 else 0
        pass_rate = (c['rollouts_passing'] / c['rollouts'] * 100) if c['rollouts'] > 0 else 0
        logger.info(
            f"  CWE-{cwe_id:3d}: "
            f"vulns {c['rollouts_with_vulns']:2d}/{c['rollouts']:<3d} ({vuln_rate:5.2f}%), "
            f"tests {c['rollouts_passing']:2d}/{c['rollouts']:<3d} ({pass_rate:5.2f}%)"
        )


@app.command()
def generate(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    model: str = typer.Option("openai/gpt-4o-mini", "--model", "-m", help="The LLM model to use for code generation (model under test)"),
    temperature: float = typer.Option(1.0, "--temperature", "-t", help="Sampling temperature for generation"),
    cwes: list[str] = typer.Option([], "--cwe", "-c", help="List of CWEs to target (e.g., CWE-79)"),
    use_top_25: bool = typer.Option(False, "--use-top-25", help="Use the top 25 most common CWEs"),
    min_samples: int = typer.Option(3, "--min-samples", '-n', help="Number of scenarios to generate per CWE"),
    num_rollouts: int = typer.Option(10, "--rollouts", '-k', help="Number of independent code rollouts per scenario"),
    output_dir: str = typer.Option('./output', "--output", "-o", help="Output directory for generated scenarios"),
    api_key: str | None = typer.Option(None, "--api-key", help="API key for the code model"),
    api_base: str | None = typer.Option(None, "--api-base", help="Base URL for the code model API"),
    test_model: str = typer.Option("openai/gpt-5.3-codex", "--test-model", help="Model for scenario/test generation (trusted)"),
    test_api_key: str | None = typer.Option(None, "--test-api-key", help="API key for the test model (defaults to --api-key)"),
    test_api_base: str | None = typer.Option(None, "--test-api-base", help="Base URL for the test model API (defaults to --api-base)"),
    analysis_tool: AnalysisTool = typer.Option(AnalysisTool.SEMGREP.value, "--analysis-tool", "-a", help="Analysis tool to use for evaluation (codeql, codex-security, semgrep, or all)"),
    reasoning_effort: str | None = typer.Option(None, "--reasoning-effort", help="Reasoning effort for code model (low, medium, high)"),
    checkpoint: str | None = typer.Option(None, "--checkpoint", help="Path to local HuggingFace model checkpoint for code generation"),
    tk_checkpoint: str | None = typer.Option(None, "--tk-checkpoint", help="Path to Tinker sampling weights for code generation"),
    tk_model: str | None = typer.Option(None, "--tk-model", help="HF model ID for tokenizer when using --tk-checkpoint (e.g. Qwen/Qwen3-4B-Instruct-2507)"),
    coder_prompt: str | None = typer.Option(None, "--coder-prompt", "-c", help="Path to a JSON file with a hardened coder prompt to load"),
    secure: bool = typer.Option(False, "--secure", "-s", help="Use the security-hardened coder signature (instructs the model to write secure code; mutually exclusive with --coder-prompt and --barebones)"),
    barebones: bool = typer.Option(False, "--barebones", "-b", help="Use the minimal/barebones coder signature (no production-quality preamble; mutually exclusive with --coder-prompt and --secure)"),
    debug_log: str | None = typer.Option(None, "--debug", help="Path to a debug log file; failing LM prompts and CWE errors will be written here as JSONL"),
):
    """Generate scenarios that induce vulnerabilities in LLM-generated code.

    Uses a two-model architecture: a trusted test model generates scenarios and
    tests, while the code model (under test) generates N independent rollouts
    per scenario for pass@N evaluation.
    """

    ctx.ensure_object(dict)
    language = ctx.obj.get("language", "python")

    config = GenerateConfig(
        verbose=verbose,
        model=model,
        temperature=temperature,
        language=language,
        cwes=cwes,
        use_top_25=use_top_25,
        min_samples=min_samples,
        num_rollouts=num_rollouts,
        output_dir=output_dir,
        api_key=api_key or os.getenv("LLM_API_KEY"),
        api_base=api_base or os.getenv("LLM_API_BASE"),
        test_model=test_model,
        test_api_key=test_api_key or os.getenv("TEST_LLM_API_KEY"),
        test_api_base=test_api_base or os.getenv("TEST_LLM_API_BASE"),
        analysis_tool=analysis_tool,
        reasoning_effort=reasoning_effort,
        checkpoint=checkpoint,
        tk_checkpoint=tk_checkpoint,
        tk_model=tk_model,
        coder_prompt=coder_prompt,
        secure=secure,
        barebones=barebones,
        debug_log=debug_log,
    )

    configure_logging(config.verbose)

    generate_scenarios(config)

@app.command()
def generate_stats(filepath: Path = typer.Argument(..., help="Path to the JSONL file with generation results")):
    """Generate statistics from the results JSONL file (supports nested scenarios/rollouts schema)."""

    total_cwes = 0
    total_scenarios = 0
    total_rollouts = 0
    total_rollouts_passing = 0
    total_rollouts_with_vulns = 0
    total_vulnerabilities = 0
    cwe_stats: Dict[int, Dict[str, int]] = {}

    # Display config info if present
    config_rec = read_config_record(filepath)
    if config_rec:
        cfg = config_rec.get("config", {})
        env = config_rec.get("environment", {})
        logger.info(f"Run config: model={cfg.get('model')}, temperature={cfg.get('temperature')}, "
                     f"rollouts={cfg.get('num_rollouts')}, analysis={cfg.get('analysis_tool')}")
        logger.info(f"Environment: python={env.get('python_version')}, "
                     f"package={env.get('package_version')}, git={env.get('git_commit')}")
        logger.info("")

    with jsonlines.open(filepath) as reader:
        for record in reader:
            if not is_data_record(record):
                continue
            cwe_id = record['cwe_id']
            total_cwes += 1

            scenarios = record.get('scenarios', [])
            total_scenarios += len(scenarios)

            cwe_rollouts = 0
            cwe_rollouts_passing = 0
            cwe_rollouts_with_vulns = 0
            cwe_vulns = 0

            for scenario in scenarios:
                rollouts = scenario.get('rollouts', [])
                cwe_rollouts += len(rollouts)

                for rollout in rollouts:
                    passes = rollout.get('passes_tests')
                    if passes is True:
                        cwe_rollouts_passing += 1

                    vulns = rollout.get('vulnerabilities', [])
                    if vulns:
                        cwe_rollouts_with_vulns += 1
                        cwe_vulns += len(vulns)

            total_rollouts += cwe_rollouts
            total_rollouts_passing += cwe_rollouts_passing
            total_rollouts_with_vulns += cwe_rollouts_with_vulns
            total_vulnerabilities += cwe_vulns

            cwe_stats[cwe_id] = {
                'scenarios': len(scenarios),
                'rollouts': cwe_rollouts,
                'rollouts_passing': cwe_rollouts_passing,
                'rollouts_with_vulns': cwe_rollouts_with_vulns,
                'vulnerabilities': cwe_vulns,
            }

    # Overall summary
    vuln_rate = (total_rollouts_with_vulns / total_rollouts * 100) if total_rollouts > 0 else 0

    logger.info(f"Total CWEs: {total_cwes}")
    logger.info(f"Total scenarios: {total_scenarios}")
    logger.info(f"Total rollouts: {total_rollouts}")
    logger.info(f"Total vulnerabilities found: {total_vulnerabilities}")
    logger.info(f"Overall vulnerability rate: {total_rollouts_with_vulns}/{total_rollouts} ({vuln_rate:.2f}%)")
    if total_rollouts > 0:
        pass_rate = total_rollouts_passing / total_rollouts * 100
        logger.info(f"Test pass rate: {total_rollouts_passing}/{total_rollouts} ({pass_rate:.2f}%)")
    logger.info("")

    # Per-CWE table sorted by decreasing vulnerability rate
    sorted_cwes = sorted(
        cwe_stats.items(),
        key=lambda item: item[1]['rollouts_with_vulns'] / item[1]['rollouts'] if item[1]['rollouts'] > 0 else 0,
        reverse=True,
    )
    logger.info("Per CWE (sorted by vulnerability rate):")
    for cwe_id, c in sorted_cwes:
        cwe_vuln_rate = (c['rollouts_with_vulns'] / c['rollouts'] * 100) if c['rollouts'] > 0 else 0
        cwe_pass_rate = (c['rollouts_passing'] / c['rollouts'] * 100) if c['rollouts'] > 0 else 0
        logger.info(
            f"  CWE-{cwe_id:3d}: "
            f"vulns {c['rollouts_with_vulns']:2d}/{c['rollouts']:<3d} ({cwe_vuln_rate:5.2f}%), "
            f"tests {c['rollouts_passing']:2d}/{c['rollouts']:<3d} ({cwe_pass_rate:5.2f}%)"
        )

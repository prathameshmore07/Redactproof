import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .pipeline import RedactproofPipeline
from .config import settings
from .input_loader import load_and_validate_image
from .gemma.injection_guard import PromptInjectionGuard

app = typer.Typer(
    name="redactproof",
    help="Redact. Re-attack. Prove. Local-first screenshot sanitizer that red-teams its own output.",
    add_completion=False,
)
console = Console()

@app.command()
def sanitize(
    input_file: Path = typer.Argument(..., help="Path to input screenshot (PNG, JPEG, HEIC)"),
    policy: str = typer.Option("public", "--policy", "-p", help="Destination policy: public, internal, support, or path to custom JSON"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Target path for sanitized image"),
    report: Optional[Path] = typer.Option(None, "--report", "-r", help="Target path for audit report JSON"),
    strict: bool = typer.Option(False, "--strict", help="Fail-closed mode: block export if review items or residual risks remain"),
    report_include_text: bool = typer.Option(False, "--report-include-text", help="Explicitly include redacted plaintext in audit report (WARNING: may leak secrets in report!)"),
    runtime: str = typer.Option("auto", "--runtime", help="Model runtime: auto, ollama, or mock"),
    margin: int = typer.Option(settings.default_margin_px, "--margin", help="Mask margin expansion in pixels"),
):
    """Sanitize a screenshot with closed-loop verification and honest audit report."""
    if report_include_text:
        console.print("[bold yellow]WARNING:[/bold yellow] --report-include-text is active. Redacted plaintext will be included in the audit report.")

    try:
        pipeline = RedactproofPipeline(
            policy_name=policy,
            gemma_runtime=runtime,
            margin_px=margin,
            strict_mode=strict,
            include_plaintext_in_report=report_include_text,
        )
    except Exception as e:
        console.print(f"[bold red]Initialization Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    with console.status("[bold cyan]Running Redactproof perception, policy & verification pipeline...", spinner="dots"):
        result = pipeline.run(
            input_path=input_file,
            output_path=output,
            report_path=report,
        )

    # 1. Findings Table
    findings_table = Table(title="Detected Regions & Applied Policy", box=box.ROUNDED)
    findings_table.add_column("ID", justify="right", style="cyan", no_wrap=True)
    findings_table.add_column("Category", style="magenta")
    findings_table.add_column("Detector", style="blue")
    findings_table.add_column("Action", style="bold")
    findings_table.add_column("Rationale", style="white")

    for f in result.findings:
        action_style = "green" if f.action.value == "keep" else "red" if f.action.value == "redact" else "yellow"
        findings_table.add_row(
            str(f.region_id),
            f.category.value,
            f.detector,
            f"[{action_style}]{f.action.value.upper()}[/{action_style}]",
            f.rationale[:60] + "..." if len(f.rationale) > 60 else f.rationale,
        )

    console.print(findings_table)

    # 2. Stranger Test Comparison Panel
    stranger_before_txt = "\n".join([f"• {inf}" for inf in result.stranger_before]) or "[italic green]No sensitive inferences drawn.[/italic green]"
    stranger_after_txt = "\n".join([f"• {inf}" for inf in result.stranger_after]) or "[bold green]✓ Zero confidential inferences remaining[/bold green]"

    stranger_panel = Panel(
        f"[bold cyan]Before Sanitization (Original):[/bold cyan]\n{stranger_before_txt}\n\n"
        f"[bold cyan]After Sanitization (Sanitized Output):[/bold cyan]\n{stranger_after_txt}",
        title="[bold yellow]Stranger Test: Outgoing Audience Inferences[/bold yellow]",
        border_style="yellow",
        box=box.ROUNDED,
    )
    console.print(stranger_panel)

    # 3. Verified Facts vs Assessed Judgments
    v = result.audit_report.verified
    a = result.audit_report.assessed

    verified_txt = (
        f"• Masks uniform color (zero variance): {'[green]PASS[/green]' if v.masks_uniform else '[red]FAIL[/red]'}\n"
        f"• Verifier OCR hits in masked regions: [bold]{v.verifier_ocr_hits_in_masks}[/bold]\n"
        f"• Pattern detector hits in output: [bold]{v.pattern_hits_after}[/bold]\n"
        f"• Trailing bytes after image marker: [bold]{v.trailing_bytes}[/bold]\n"
        f"• Metadata markers remaining: [bold]{v.metadata_markers_found}[/bold]"
    )

    assessed_txt = (
        f"• Adversary residual findings: [bold]{a.adversary_residual_findings}[/bold]\n"
        f"• Automated fix passes used: [bold]{a.fix_passes_used}[/bold]\n"
        f"• Residual risk level: [yellow]{result.audit_report.residual_risk.level}[/yellow]"
    )

    summary_panel = Panel(
        f"[bold green]Verified Deterministic Facts:[/bold green]\n{verified_txt}\n\n"
        f"[bold blue]Assessed Model Judgments (Gemma 4):[/bold blue]\n{assessed_txt}",
        title="[bold white]Verification Loop & Re-Attack Audit[/bold white]",
        border_style="green" if result.success else "red",
        box=box.ROUNDED,
    )
    console.print(summary_panel)

    if result.blocked:
        console.print(f"[bold red]EXPORT BLOCKED:[/bold red] Strict policy blocked export due to findings (Exit code {result.exit_code})")
    elif result.output_path:
        console.print(f"[bold green]✓ Sanitized Image Written:[/bold green] {result.output_path}")
        if report:
            console.print(f"[bold green]✓ Audit Report Written:[/bold green] {report}")

    sys.exit(result.exit_code)

@app.command()
def check(
    input_file: Path = typer.Argument(..., help="Path to input screenshot to check"),
    policy: str = typer.Option("public", "--policy", "-p", help="Destination policy to enforce"),
    runtime: str = typer.Option("auto", "--runtime", help="Model runtime: auto, ollama, or mock"),
):
    """Developer-native pre-commit / CI check mode. Exits with code 1 if sensitive content is found."""
    try:
        pipeline = RedactproofPipeline(
            policy_name=policy,
            gemma_runtime=runtime,
            strict_mode=True,
        )
    except Exception as e:
        console.print(f"[bold red]Initialization Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    with console.status("[bold cyan]Scanning screenshot for policy violations...", spinner="dots"):
        # Load and run perception + policy without saving output
        loaded = load_and_validate_image(input_file)
        text_items = pipeline.ocr_primary.extract_text(loaded.image)
        faces = pipeline.face_detector.detect_faces(loaded.image)
        codes = pipeline.code_detector.detect_codes(loaded.image)
        salt = "redactproof-check"
        detectors_findings = pipeline.detectors.detect_all(
            items=text_items,
            allowlist_domains=pipeline.policy.allowlist.domains,
            salt=salt,
        )
        injections = PromptInjectionGuard.inspect_text_items(text_items)
        all_det = faces + codes + detectors_findings + injections
        gemma_finds, _ = pipeline.gemma.review_ambiguous_and_relational(text_items, policy)
        final_findings = pipeline.policy_engine.apply_policy(all_det, gemma_finds)

    violations = [f for f in final_findings if f.action.value in ("redact", "review")]
    if violations:
        console.print(f"[bold red]FAILED:[/bold red] Screenshot '{input_file.name}' contains {len(violations)} policy violations under '{policy}' policy:")
        for v in violations:
            console.print(f"  • [{v.category.value}] {v.rationale} (Action: {v.action.value})")
        raise typer.Exit(code=1)
    else:
        console.print(f"[bold green]PASSED:[/bold green] Screenshot '{input_file.name}' is clean under '{policy}' policy.")
        raise typer.Exit(code=0)

@app.command()
def review(
    input_file: Optional[Path] = typer.Argument(None, help="Path to screenshot to review (optional, or upload directly in the UI)"),
    port: int = typer.Option(8000, "--port", "-P", help="Port for local review server"),
    policy: str = typer.Option("public", "--policy", "-p", help="Initial destination policy"),
):
    """Launch local web review interface bound to localhost."""
    from .review.server import start_review_server
    console.print(f"[bold cyan]Starting Redactproof Review UI at http://127.0.0.1:{port}[/bold cyan]")
    start_review_server(input_file, policy=policy, port=port)

@app.command()
def bench(
    samples: int = typer.Option(10, "--samples", "-n", help="Number of benchmark screenshots to generate and evaluate"),
):
    import sys
    from pathlib import Path
    workspace_root = Path.cwd()
    if str(workspace_root) not in sys.path:
        sys.path.insert(0, str(workspace_root))
    from bench.runners.benchmark_suite import run_redactbench
    console.print(f"[bold cyan]Launching RedactBench ({samples} synthetic samples)...[/bold cyan]")
    run_redactbench(sample_count=samples)

if __name__ == "__main__":
    app()

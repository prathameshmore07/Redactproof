import time
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Tuple
from rich.console import Console
from rich.table import Table
from rich import box

from ..generator.renderer import SyntheticScreenshotRenderer
from .baselines import BaselineEvaluator
from redactproof.perception.ocr_apple_vision import AppleVisionOCR

def check_leak_rate(held_out_ocr: AppleVisionOCR, sanitized_image, ground_truth_items) -> Tuple[int, int, int]:
    """Uses held-out OCR to count how many sensitive ground-truth items remain readable."""
    ocr_results = held_out_ocr.extract_text(sanitized_image)
    surviving_text = " ".join([r.text for r in ocr_results])

    sensitive_items = [it for it in ground_truth_items if it.is_sensitive]
    safe_items = [it for it in ground_truth_items if not it.is_sensitive]

    leaks = 0
    for s in sensitive_items:
        # Check if sensitive token is recoverable in surviving text
        token_snippet = s.text[:8]
        if token_snippet in surviving_text:
            leaks += 1

    # Check unnecessary redactions
    unnecessary = 0
    for safe in safe_items:
        if safe.text not in surviving_text:
            unnecessary += 1

    return leaks, len(sensitive_items), unnecessary

def run_redactbench(sample_count: int = 10):
    console = Console()
    console.print(f"[bold cyan]Generating {sample_count} synthetic ground-truth test screenshots...[/bold cyan]")

    renderer = SyntheticScreenshotRenderer()
    evaluator = BaselineEvaluator(runtime="mock")
    held_out_ocr = AppleVisionOCR(recognition_level="fast")

    systems = [
        "Regex only",
        "OCR + NER",
        "Gemma only",
        "Redactproof (no verify)",
        "Redactproof (full)",
    ]

    stats: Dict[str, Dict[str, Any]] = {
        s: {"leaks": 0, "total_sensitive": 0, "unnecessary": 0, "total_safe": 0, "latency": 0.0}
        for s in systems
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_dir = Path(tmpdir)

        for i in range(sample_count):
            img, gt_items = renderer.render_sample(i)
            safe_count = sum(1 for it in gt_items if not it.is_sensitive)

            for s in systems:
                start_t = time.perf_counter()
                if s == "Regex only":
                    out = evaluator.run_regex_only(img)
                elif s == "OCR + NER":
                    out = evaluator.run_ocr_ner(img)
                elif s == "Gemma only":
                    out = evaluator.run_gemma_only(img)
                elif s == "Redactproof (no verify)":
                    out = evaluator.run_redactproof_no_verify(img)
                elif s == "Redactproof (full)":
                    tmp_out = temp_dir / f"sample_{i}_{s.replace(' ', '_')}.png"
                    out = evaluator.run_redactproof_full(img, tmp_out)
                dur = time.perf_counter() - start_t

                leaks, total_sens, unnec = check_leak_rate(held_out_ocr, out, gt_items)
                stats[s]["leaks"] += leaks
                stats[s]["total_sensitive"] += total_sens
                stats[s]["unnecessary"] += unnec
                stats[s]["total_safe"] += safe_count
                stats[s]["latency"] += dur

    # Render results table
    table = Table(title="RedactBench Evaluation Results", box=box.ROUNDED)
    table.add_column("System / Approach", style="bold cyan")
    table.add_column("Sensitive Leak Rate (↓)", justify="center", style="bold")
    table.add_column("Recall (↑)", justify="center")
    table.add_column("Unnecessary Redaction", justify="center")
    table.add_column("Avg Latency", justify="center")

    results_md = ["# RedactBench Evaluation Results\n", "| Approach | Leak Rate (↓) | Recall (↑) | Unnecessary Redaction | Avg Latency |", "|---|---|---|---|---|"]

    for s in systems:
        tot_sens = stats[s]["total_sensitive"] or 1
        tot_safe = stats[s]["total_safe"] or 1
        leaks = stats[s]["leaks"]
        leak_rate = (leaks / tot_sens) * 100.0
        recall = 100.0 - leak_rate
        unnec_rate = (stats[s]["unnecessary"] / tot_safe) * 100.0
        avg_lat = stats[s]["latency"] / sample_count

        leak_style = "green" if leak_rate <= 5.0 else "yellow" if leak_rate <= 25.0 else "red"
        table.add_row(
            s,
            f"[{leak_style}]{leak_rate:.1f}%[/{leak_style}]",
            f"{recall:.1f}%",
            f"{unnec_rate:.1f}%",
            f"{avg_lat*1000:.1f} ms",
        )
        results_md.append(f"| {s} | {leak_rate:.1f}% | {recall:.1f}% | {unnec_rate:.1f}% | {avg_lat*1000:.1f} ms |")

    console.print(table)

    # Save to bench/results/latest.md
    res_path = Path("bench/results/latest.md")
    res_path.parent.mkdir(parents=True, exist_ok=True)
    res_path.write_text("\n".join(results_md) + "\n", encoding="utf-8")
    console.print(f"[bold green]✓ Benchmark results saved to {res_path}[/bold green]")

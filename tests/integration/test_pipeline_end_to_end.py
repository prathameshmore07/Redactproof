import tempfile
from pathlib import Path
from PIL import Image, ImageDraw
from redactproof.pipeline import RedactproofPipeline

def test_pipeline_end_to_end():
    with tempfile.TemporaryDirectory() as tmpdir:
        input_img_path = Path(tmpdir) / "test_screen.png"
        output_img_path = Path(tmpdir) / "test_screen.sanitized.png"
        report_path = Path(tmpdir) / "test_report.json"

        # Create test screenshot with secrets
        img = Image.new("RGB", (800, 400), color=(20, 20, 20))
        draw = ImageDraw.Draw(img)
        draw.text((20, 20), "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE", fill=(255, 255, 255))
        draw.text((20, 60), "Contact: devops@internal-corp.net", fill=(255, 255, 255))
        draw.text((20, 100), "Server: auth.staging.cluster.local", fill=(255, 255, 255))
        img.save(input_img_path, format="PNG")

        pipeline = RedactproofPipeline(
            policy_name="public",
            gemma_runtime="mock",
            strict_mode=False,
        )

        result = pipeline.run(
            input_path=input_img_path,
            output_path=output_img_path,
            report_path=report_path,
        )

        assert result.success is True
        assert result.exit_code == 0
        assert output_img_path.exists()
        assert report_path.exists()

        report = result.audit_report
        assert report.status == "sanitized_verified_with_residual_model_risk"
        assert report.verified.masks_uniform is True
        assert report.verified.input_unmodified is True
        assert report.transformations["regions_redacted"] >= 2
        assert len(report.assessed.stranger_test_before) > 0

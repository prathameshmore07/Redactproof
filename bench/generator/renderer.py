from typing import List, Dict, Any, Tuple
from PIL import Image, ImageDraw, ImageFont
from .fake_secrets import FakeSecretFactory
from redactproof.schemas import BoundingBox

class GroundTruthItem:
    def __init__(self, text: str, bbox: BoundingBox, category: str, is_sensitive: bool):
        self.text = text
        self.bbox = bbox
        self.category = category
        self.is_sensitive = is_sensitive

class SyntheticScreenshotRenderer:
    """Renders synthetic realistic screenshots with ground-truth bounding boxes."""

    def __init__(self, seed: int = 100):
        self.factory = FakeSecretFactory(seed=seed)

    def render_sample(self, index: int) -> Tuple[Image.Image, List[GroundTruthItem]]:
        width, height = 960, 640
        # Dark modern theme
        img = Image.new("RGB", (width, height), color=(15, 23, 42))
        draw = ImageDraw.Draw(img)

        # Draw terminal title bar
        draw.rectangle([(0, 0), (width, 36)], fill=(30, 41, 59))
        draw.ellipse([(14, 12), (24, 22)], fill=(239, 68, 68))
        draw.ellipse([(32, 12), (42, 22)], fill=(245, 158, 11))
        draw.ellipse([(50, 12), (60, 22)], fill=(16, 185, 129))
        draw.text((80, 10), f"terminal - debug-session-{index}.log", fill=(148, 163, 184))

        # Content lines
        items: List[GroundTruthItem] = []
        y = 55
        line_height = 28

        # Line 1: Safe command
        safe1 = self.factory.fake_safe_item()
        draw.text((25, y), f"$ {safe1}", fill=(241, 245, 249))
        items.append(GroundTruthItem(text=safe1, bbox=BoundingBox(x1=25, y1=y, x2=25 + len(safe1)*8, y2=y+20), category="safe", is_sensitive=False))
        y += line_height

        # Line 2: AWS Key or Secret
        aws = self.factory.fake_aws_key()
        line2 = f"Exporting AWS_ACCESS_KEY_ID={aws}"
        draw.text((25, y), line2, fill=(226, 232, 240))
        items.append(GroundTruthItem(text=aws, bbox=BoundingBox(x1=25 + 23*8, y1=y, x2=25 + len(line2)*8, y2=y+20), category="credential", is_sensitive=True))
        y += line_height

        # Line 3: Email / Customer
        email = self.factory.fake_email()
        line3 = f"Customer Account: {email} (Plan: Enterprise Tier)"
        draw.text((25, y), line3, fill=(226, 232, 240))
        items.append(GroundTruthItem(text=email, bbox=BoundingBox(x1=25 + 18*8, y1=y, x2=25 + (18+len(email))*8, y2=y+20), category="personal_identity", is_sensitive=True))
        y += line_height

        # Line 4: Internal Staging Host
        host = self.factory.fake_internal_host()
        line4 = f"Connecting to cluster endpoint: https://{host}:8443/status"
        draw.text((25, y), line4, fill=(226, 232, 240))
        items.append(GroundTruthItem(text=host, bbox=BoundingBox(x1=25 + 40*8, y1=y, x2=25 + (40+len(host))*8, y2=y+20), category="internal_hostname", is_sensitive=True))
        y += line_height

        # Line 5: Local user path
        lpath = self.factory.fake_local_path()
        line5 = f"Traceback error loading file: {lpath}"
        draw.text((25, y), line5, fill=(248, 113, 113))
        items.append(GroundTruthItem(text=lpath, bbox=BoundingBox(x1=25 + 30*8, y1=y, x2=25 + (30+len(lpath))*8, y2=y+20), category="local_path_user", is_sensitive=True))
        y += line_height

        # Line 6: In every 3rd sample, add an adversarial prompt injection
        if index % 3 == 0:
            inj = self.factory.fake_prompt_injection()
            draw.text((25, y), f"# {inj}", fill=(148, 163, 184))
            items.append(GroundTruthItem(text=inj, bbox=BoundingBox(x1=25, y1=y, x2=25 + len(inj)*8, y2=y+20), category="prompt_injection_attempt", is_sensitive=True))
            y += line_height

        # Line 7: Safe docs URL
        safe2 = "Documentation: https://docs.python.org/3/library/os.path.html"
        draw.text((25, y), safe2, fill=(56, 189, 248))
        items.append(GroundTruthItem(text="https://docs.python.org/3/library/os.path.html", bbox=BoundingBox(x1=25 + 15*8, y1=y, x2=25 + len(safe2)*8, y2=y+20), category="safe", is_sensitive=False))

        return img, items

from typing import List, Tuple
from ..schemas import TextItem
from ..gemma.client import GemmaClient

class ModelAdversaryVerifier:
    """Invokes Gemma 4 adversary and Stranger Test comparison on output."""

    def __init__(self, gemma_client: GemmaClient):
        self.client = gemma_client

    def run_adversary(
        self,
        output_text_items: List[TextItem],
        destination: str,
    ) -> Tuple[bool, List[str]]:
        return self.client.adversary_attack(output_text_items, destination)

    def run_stranger_test(
        self,
        output_text_items: List[TextItem],
        destination: str,
    ) -> List[str]:
        return self.client.stranger_test(output_text_items, destination)

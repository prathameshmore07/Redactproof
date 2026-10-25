"""
Redactproof Studio Entry Point.
Run with:
    streamlit run app.py
"""
import sys
from pathlib import Path

# Ensure src/ is on python path
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from redactproof.streamlit_app.app import main

if __name__ == "__main__":
    main()

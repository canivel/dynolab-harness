import os
import sys
import tempfile
from pathlib import Path

# Tests must never read or write a real user's data directory.
os.environ["HARNESS_HOME"] = tempfile.mkdtemp(prefix="harness-test-home-")

sys.path.insert(0, str(Path(__file__).parent))

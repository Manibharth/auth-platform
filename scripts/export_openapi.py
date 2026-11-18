"""Write the OpenAPI document; CI diffs it against the committed snapshot."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ENVIRONMENT", "test")

from app.core.config import Settings
from app.main import create_app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="openapi/openapi.json")
    args = parser.parse_args()
    app = create_app(Settings(_env_file=None, environment="test"))  # type: ignore[call-arg]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

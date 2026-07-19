from __future__ import annotations

import logging
import sys
from pathlib import Path


def configure_logging(app_root: Path) -> None:
    log_dir = app_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_dir / "netwatch_ai.log", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def main() -> int:
    app_root = Path(__file__).resolve().parent
    configure_logging(app_root)
    for folder in ["database", "reports", "models", "assets", "logs"]:
        (app_root / folder).mkdir(parents=True, exist_ok=True)

    try:
        from gui.app import run_app
    except ImportError as exc:
        print("NetWatch AI could not start because a GUI dependency is missing.")
        print("Install dependencies with: python -m pip install -r requirements.txt")
        print(f"Details: {exc}")
        return 1

    run_app(app_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


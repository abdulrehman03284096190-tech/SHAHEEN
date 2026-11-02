from __future__ import annotations

from config.settings import load_settings
from core.application import ShaheenApplication
from gui.main_window import launch


def main() -> None:
    settings = load_settings()
    app = ShaheenApplication(settings)
    launch(app)


if __name__ == "__main__":
    main()

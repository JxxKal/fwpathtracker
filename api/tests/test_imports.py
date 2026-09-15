"""Die App muss importierbar sein — jeder Router, jedes Modul.

Ein Syntaxfehler in einem Router fällt sonst erst beim Container-Start auf
(Feld-Fall: ASCII-Anführungszeichen in einem deutschen „Zitat" beendete einen
String — alle Fachtests grün, API tot).
"""
from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))


def test_app_and_all_modules_import():
    import main  # noqa: F401  — zieht alle Router

    failed = []
    for mod in pkgutil.walk_packages([str(SRC)]):
        try:
            importlib.import_module(mod.name)
        except Exception as exc:  # pragma: no cover — genau das soll auffallen
            failed.append(f"{mod.name}: {exc}")
    assert not failed, "\n".join(failed)

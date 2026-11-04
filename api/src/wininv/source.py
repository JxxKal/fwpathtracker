"""Woher die Dateien kommen: SMB-Freigabe (\\\\server\\share[\\pfad]) oder ein
lokales Verzeichnis (eingehängte Freigabe, Tests, Demo)."""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Entry:
    name: str
    size: int
    mtime: datetime


class SourceError(Exception):
    pass


def is_unc(path: str) -> bool:
    return path.startswith("\\\\") or path.startswith("//")


def unc_parts(path: str) -> tuple[str, str]:
    """'\\\\svo3001-ot\\Inventory$\\Daten' → ('svo3001-ot', '\\\\svo3001-ot\\Inventory$\\Daten')."""
    norm = "\\\\" + path.replace("/", "\\").lstrip("\\")
    parts = [p for p in norm.split("\\") if p]
    if len(parts) < 2:
        raise SourceError("Pfad muss \\\\server\\freigabe lauten.")
    return parts[0], norm.rstrip("\\")


class LocalSource:
    def __init__(self, path: str) -> None:
        self.path = Path(path)

    async def list(self) -> list[Entry]:
        def scan() -> list[Entry]:
            if not self.path.is_dir():
                raise SourceError(f"Verzeichnis {self.path} gibt es nicht.")
            out = []
            with os.scandir(self.path) as it:
                for e in it:
                    if e.is_file():
                        st = e.stat()
                        out.append(Entry(e.name, st.st_size,
                                         datetime.fromtimestamp(st.st_mtime, timezone.utc)))
            return out
        return await asyncio.to_thread(scan)

    async def read(self, name: str) -> bytes:
        return await asyncio.to_thread((self.path / name).read_bytes)

    async def close(self) -> None:
        return None


class SmbSource:
    """Nur lesend. smbclient ist synchron → Aufrufe im Thread."""

    def __init__(self, path: str, username: str, password: str, timeout: int = 30) -> None:
        self.server, self.path = unc_parts(path)
        self.username, self.password, self.timeout = username, password, timeout
        self._session = False

    def _connect(self) -> None:
        import smbclient
        if not self._session:
            smbclient.register_session(self.server, username=self.username or None,
                                       password=self.password or None,
                                       connection_timeout=self.timeout)
            self._session = True

    async def list(self) -> list[Entry]:
        def scan() -> list[Entry]:
            import smbclient
            self._connect()
            out = []
            for e in smbclient.scandir(self.path):
                if e.is_file():
                    st = e.stat()
                    out.append(Entry(e.name, st.st_size,
                                     datetime.fromtimestamp(st.st_mtime, timezone.utc)))
            return out
        try:
            return await asyncio.to_thread(scan)
        except SourceError:
            raise
        except Exception as exc:
            raise SourceError(f"{self.path}: {exc}") from exc

    async def read(self, name: str) -> bytes:
        def get() -> bytes:
            import smbclient
            self._connect()
            with smbclient.open_file(f"{self.path}\\{name}", mode="rb") as fh:
                return fh.read()
        return await asyncio.to_thread(get)

    async def close(self) -> None:
        def drop() -> None:
            import smbclient
            try:
                smbclient.delete_session(self.server)
            except Exception:
                pass
        if self._session:
            await asyncio.to_thread(drop)
            self._session = False


def build_source(cfg: dict):
    path = (cfg.get("path") or "").strip()
    if not path:
        raise SourceError("Kein Pfad konfiguriert.")
    if is_unc(path):
        return SmbSource(path, cfg.get("username") or "", cfg.get("password") or "",
                         int(cfg.get("timeout_s") or 30))
    return LocalSource(path)

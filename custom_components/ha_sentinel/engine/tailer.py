"""Incremental, rotation-aware log file reader (``tail -F`` semantics)."""

from __future__ import annotations

import os
from pathlib import Path

_MAX_LINE = 8192


class LogTailer:
    """Return only the lines appended to a file since the previous call.

    * On first open it starts at the end of the file (history is not replayed)
      unless ``from_start`` is True.
    * Detects rotation (inode change) and truncation (size shrinks) and then
      restarts from the beginning of the new file.
    * Keeps a partial trailing line buffered until its newline arrives.
    """

    def __init__(self, path: str | Path, *, from_start: bool = False) -> None:
        self.path = Path(path)
        self._from_start = from_start
        self._inode: int | None = None
        self._offset = 0
        self._partial = b""
        self.error: str | None = None

    def read_new_lines(self, max_bytes: int = 4 * 1024 * 1024) -> list[str]:
        """Read appended lines (blocking I/O: run it in an executor)."""
        try:
            st = os.stat(self.path)
        except OSError as err:
            self.error = str(err)
            return []
        self.error = None

        if self._inode is None:
            self._inode = st.st_ino
            self._offset = 0 if self._from_start else st.st_size
        elif st.st_ino != self._inode or st.st_size < self._offset:
            self._inode = st.st_ino
            self._offset = 0
            self._partial = b""

        if st.st_size == self._offset:
            return []

        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read(max_bytes)
        except OSError as err:
            self.error = str(err)
            return []
        self._offset += len(chunk)

        data = self._partial + chunk
        lines = data.split(b"\n")
        self._partial = lines.pop()  # incomplete trailing line (or b"")
        if len(self._partial) > _MAX_LINE:
            self._partial = b""
        return [line[:_MAX_LINE].decode("utf-8", errors="replace").rstrip("\r") for line in lines if line]

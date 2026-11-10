"""Tests for the rotation-aware log tailer."""

from __future__ import annotations

import os
from pathlib import Path

from custom_components.ha_sentinel.engine.tailer import LogTailer


def test_starts_at_end_and_reads_appends(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("old line\n")
    tailer = LogTailer(log)
    assert tailer.read_new_lines() == []

    with log.open("a") as fh:
        fh.write("new 1\nnew 2\n")
    assert tailer.read_new_lines() == ["new 1", "new 2"]
    assert tailer.read_new_lines() == []


def test_partial_line_is_buffered(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("")
    tailer = LogTailer(log)
    tailer.read_new_lines()
    with log.open("a") as fh:
        fh.write("hal")
    assert tailer.read_new_lines() == []
    with log.open("a") as fh:
        fh.write("f\n")
    assert tailer.read_new_lines() == ["half"]


def test_rotation_and_truncation(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("x\n")
    tailer = LogTailer(log)
    tailer.read_new_lines()

    os.rename(log, tmp_path / "a.log.1")
    log.write_text("rotated\n")
    assert tailer.read_new_lines() == ["rotated"]

    log.write_text("")  # truncate in place
    tailer.read_new_lines()
    with log.open("a") as fh:
        fh.write("after truncate\n")
    assert tailer.read_new_lines() == ["after truncate"]


def test_missing_file_sets_error(tmp_path: Path) -> None:
    tailer = LogTailer(tmp_path / "nope.log")
    assert tailer.read_new_lines() == []
    assert tailer.error


def test_from_start(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    log.write_text("a\nb\n")
    assert LogTailer(log, from_start=True).read_new_lines() == ["a", "b"]

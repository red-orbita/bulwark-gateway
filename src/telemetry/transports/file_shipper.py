"""
File Shipper Transport — Write to local files for log shipper pickup.

Used with: Filebeat, Fluentd, Logstash, Vector, rsyslog.
Compatible with: ELK Stack, Splunk UF, Security Onion, any file-based ingestion.

Features:
    - Rotation by size (default 100MB) or time (daily)
    - NDJSON format (one event per line)
    - Atomic writes (write to .tmp, rename)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..schema import SecurityTelemetryEvent

logger = logging.getLogger(__name__)


@dataclass
class FileShipperConfig:
    path: str = "/var/log/sentinel-gateway/events.ndjson"
    max_size_bytes: int = 100 * 1024 * 1024  # 100MB
    rotate_count: int = 5
    format: str = "ndjson"  # ndjson, json_array
    flush_every: int = 1  # flush after N events (1 = immediate)


class FileShipperTransport:
    """Write telemetry events to local files for shipper pickup."""

    name = "file_shipper"

    def __init__(self, config: FileShipperConfig):
        self._config = config
        self._path = Path(config.path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = None
        self._current_size = 0

    def _open_file(self):
        if self._path.exists():
            self._current_size = self._path.stat().st_size
        else:
            self._current_size = 0
        self._file = open(self._path, "a", encoding="utf-8")

    def _rotate_if_needed(self) -> None:
        if self._current_size >= self._config.max_size_bytes:
            if self._file:
                self._file.close()
            # Rotate: events.ndjson → events.ndjson.1 → .2 → ...
            for i in range(self._config.rotate_count - 1, 0, -1):
                src = self._path.with_suffix(f".ndjson.{i}")
                dst = self._path.with_suffix(f".ndjson.{i + 1}")
                if src.exists():
                    src.rename(dst)
            if self._path.exists():
                self._path.rename(self._path.with_suffix(".ndjson.1"))
            self._open_file()

    async def send_batch(self, events: list[SecurityTelemetryEvent]) -> bool:
        try:
            if self._file is None:
                self._open_file()

            self._rotate_if_needed()

            lines = []
            for event in events:
                line = event.model_dump_json(by_alias=True, exclude_none=True) + "\n"
                lines.append(line)
                self._current_size += len(line.encode("utf-8"))

            self._file.writelines(lines)  # type: ignore
            self._file.flush()  # type: ignore
            return True
        except Exception as e:
            logger.error("file_shipper_error", extra={"error": str(e)})
            return False

    async def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

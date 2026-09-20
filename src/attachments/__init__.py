"""Scoped, bounded attachment persistence; no parser or service startup."""

from .store import AttachmentStore, StoreError, get_attachment_store

__all__ = ["AttachmentStore", "StoreError", "get_attachment_store"]

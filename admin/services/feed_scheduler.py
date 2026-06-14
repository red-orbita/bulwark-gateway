"""Feed Scheduler — Background asyncio task for periodic IOC feed updates."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.feed_scheduler")


class FeedScheduler:
    """Runs periodic feed updates based on each feed's interval_minutes."""

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        """Start the scheduler loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Feed scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Feed scheduler stopped")

    async def _loop(self) -> None:
        """Main scheduler loop — checks every 60s which feeds are due."""
        # Wait a bit on startup to let the app fully initialize
        await asyncio.sleep(10)

        while self._running:
            try:
                await self._check_feeds()
            except Exception as e:
                logger.error(f"Feed scheduler error: {e}")
            await asyncio.sleep(60)

    async def _check_feeds(self) -> None:
        """Check all enabled feeds and trigger those that are due."""
        from .ioc_store import get_ioc_store

        store = get_ioc_store()
        feeds = store.list_feeds()
        now = datetime.now(timezone.utc)

        for feed in feeds:
            if not feed.enabled:
                continue

            # Determine if feed is due
            if feed.last_run:
                try:
                    last = datetime.fromisoformat(feed.last_run.replace("Z", "+00:00"))
                    elapsed_minutes = (now - last).total_seconds() / 60
                    if elapsed_minutes < feed.interval_minutes:
                        continue
                except (ValueError, TypeError):
                    pass  # If can't parse, run it

            # Run in executor to not block the event loop (fetchers use requests/httpx sync)
            loop = asyncio.get_event_loop()
            try:
                logger.info(f"Scheduler triggering feed: {feed.name} ({feed.id})")
                result = await loop.run_in_executor(
                    None, store.trigger_feed_update, feed.id
                )
                feed_result = result.get(feed.id, {})
                if feed_result.get("status") == "ok":
                    logger.info(f"Feed {feed.name}: {feed_result.get('count', 0)} IOCs added")
                else:
                    logger.warning(f"Feed {feed.name} error: {feed_result.get('error', 'unknown')}")
            except Exception as e:
                logger.error(f"Feed {feed.name} scheduler error: {e}")


# Singleton
_scheduler: FeedScheduler | None = None


def get_feed_scheduler() -> FeedScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = FeedScheduler()
    return _scheduler

"""Main entry point for all workers - runs all workers in a single process."""
import asyncio
import signal
import sys
from typing import List

from shared.logging.config import configure_logging, get_logger

# Import all workers
from transcribe.worker import TranscribeWorker
from summarize.worker import SummarizeWorker
from embed.worker import EmbedWorker
from relationships.worker import RelationshipsWorker
from worker_utils.base_worker import BaseWorker

logger = get_logger(__name__)


async def run_all_workers(workers: List[BaseWorker]) -> None:
    """Run all workers concurrently."""
    # Set up signal handlers
    stop_event = asyncio.Event()
    
    def handle_signal(signum: int, frame) -> None:
        logger.info("Received shutdown signal", signal=signum)
        for worker in workers:
            worker.stop()
        stop_event.set()
    
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    
    # Start all workers
    logger.info("Starting all workers", count=len(workers))
    tasks = [asyncio.create_task(worker.run()) for worker in workers]
    
    # Wait for all workers to complete (they run until stopped)
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        logger.exception("Error running workers", error=str(e))
    
    logger.info("All workers stopped")


def main() -> None:
    """Main entry point."""
    configure_logging()
    logger.info("Initializing workers...")
    
    # Create all worker instances
    workers = [
        TranscribeWorker(),
        SummarizeWorker(),
        EmbedWorker(),
        RelationshipsWorker(),
    ]
    
    logger.info("Workers initialized", workers=[type(w).__name__ for w in workers])
    
    try:
        asyncio.run(run_all_workers(workers))
    except KeyboardInterrupt:
        pass
    finally:
        sys.exit(0)


if __name__ == "__main__":
    main()

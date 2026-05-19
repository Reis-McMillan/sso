"""Integration test for OpenObserve log ingestion.

Not prefixed with test_ to prevent automatic pytest discovery.
Run directly: python tests/integration/openobserve.py

Requires OPENOBSERVE_ENDPOINT and OPENOBSERVE_TOKEN environment variables to be set.
"""
import logging

from verys.config import config
from verys.modules.logging import OpenObserveHandler


def test_log_ingestion():
    endpoint = config.OPENOBSERVE_ENDPOINT
    token = config.OPENOBSERVE_TOKEN

    if not endpoint or not token:
        print("OPENOBSERVE_ENDPOINT and OPENOBSERVE_TOKEN must be set")
        return

    handler = OpenObserveHandler(
        endpoint=endpoint,
        token=token,
        stream='test-verys',
        batch_size=1,
        flush_interval=60.0,
    )
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    logger = logging.getLogger("verys.integration_test")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    logger.info("Integration test - INFO level")
    logger.warning("Integration test - WARNING level")
    logger.error("Integration test - ERROR level")

    # flush and close to ensure all logs are sent
    handler.close()

    print(f"3 log entries sent to {handler.url}")
    print("Check OpenObserve UI to verify ingestion")


if __name__ == "__main__":
    test_log_ingestion()

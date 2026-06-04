"""Runtime constants for LAN Watcher Pro.

The current implementation keeps constants in ``lan_watcher.cli`` for backward
compatibility while the public package surface is being stabilized.
"""

from .cli import (
    COMMON_TCP_PORTS,
    DEFAULT_OFFLINE_AFTER,
    DEFAULT_OFFLINE_FAIL_THRESHOLD,
    DEFAULT_PROFILE,
    DEFAULT_STATE_FILE,
    DEFAULT_SWEEP_INTERVAL,
    DEFAULT_TCP_WORKERS,
    DEFAULT_TRAFFIC_WINDOW,
    DEFAULT_UI_INTERVAL,
    FAST_QUEUE_MAX,
    OBSERVATION_QUEUE_MAX,
    SCHEMA_VERSION,
    SLOW_QUEUE_MAX,
)

"""Compatibility entrypoint for LAN Watcher Pro.

The implementation lives in the ``lan_watcher`` package. Keep this file so
existing launchers and commands continue to work:

    python realtime_lan_watcher_deep.py --profile aggressive
"""

from lan_watcher.cli import main


if __name__ == "__main__":
    main()

"""Backward-compatible alias for the ADK CLI.

Delegates to :mod:`client_inmemory_v2_google_adk`. Prefer importing or running that
module directly.
"""

from client_inmemory_v2_google_adk import *  # noqa: F403

if __name__ == "__main__":
    import asyncio

    try:
        asyncio.run(run_intelligent_agent())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting...")

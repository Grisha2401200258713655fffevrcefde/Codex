from __future__ import annotations

import logging
import os
import signal
import threading

from .core import Config, Database, Engine
from .runtime_patch import apply_runtime_patches
from .web import AppServer


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LYNX_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    apply_runtime_patches()
    config = Config(os.getenv("LYNX_CONFIG", "/app/config/hosts.json"))
    db = Database(os.getenv("LYNX_DB", "/app/data/lynxbrain.db"))
    engine = Engine(config, db)
    server = AppServer(
        (os.getenv("LYNX_BIND", "0.0.0.0"), int(os.getenv("LYNX_PORT", "8088"))),
        engine,
        os.getenv("LYNX_API_TOKEN", ""),
    )
    threading.Thread(target=engine.run_forever, name="lynx-engine", daemon=True).start()

    def stop(*_: object) -> None:
        engine.stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.serve_forever(poll_interval=0.5)
    server.server_close()


if __name__ == "__main__":
    main()

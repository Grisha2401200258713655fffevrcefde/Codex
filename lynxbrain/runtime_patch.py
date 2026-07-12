from __future__ import annotations

from typing import Any

from .core import Collector, Metric


_ORIGINAL_COLLECT = Collector.collect


def apply_runtime_patches() -> None:
    """Apply safe compatibility fixes without exposing the host Docker socket."""

    def collect(self: Collector, host: dict[str, Any]) -> list[Metric]:
        metrics = _ORIGINAL_COLLECT(self, host)

        # A local-mode target runs inside the LynxBrain container. Without the
        # host Docker socket, docker info describes container access rather
        # than the physical host and causes a false docker_engine_down alarm.
        # Docker monitoring remains available for SSH targets and for any
        # future explicitly configured integration.
        if host.get("mode") == "local" and not host.get("monitor_docker", False):
            metrics = [metric for metric in metrics if metric.name != "docker_up"]

        return metrics

    Collector.collect = collect

import json
import tempfile
import unittest
from pathlib import Path

from lynxbrain.core import ActionPlanner, Analyzer, Config, ConfigError, Database, IncidentCandidate, Metric


class LynxBrainTests(unittest.TestCase):
    def test_robust_zscore_detects_spike(self):
        history = [10, 11, 9, 10, 12, 10, 11, 9, 10, 10]
        self.assertGreater(Analyzer.robust_zscore(90, history), 10)

    def test_robust_zscore_accepts_normal_value(self):
        history = [10, 11, 9, 10, 12, 10, 11, 9, 10, 10]
        self.assertLess(Analyzer.robust_zscore(11, history), 3)

    def test_config_rejects_shell_injection_target(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "hosts.json"
            path.write_text(json.dumps({"hosts": [{"name": "node-1", "address": "127.0.0.1", "containers": ["app;rm -rf /"], "services": [], "allowed_actions": []}]}))
            with self.assertRaises(ConfigError): Config(str(path))

    def test_disk_pressure_is_correlated(self):
        with tempfile.TemporaryDirectory() as td:
            db = Database(str(Path(td) / "test.db")); analyzer = Analyzer(db, history_window=100, min_samples=20)
            metrics = [Metric("reachable", 1), Metric("ssh_reachable", 1), Metric("root_used_pct", 97)]
            incident = analyzer.correlate({"name": "node-1", "importance": 8}, metrics, analyzer.detect("node-1", metrics))
            self.assertEqual(incident.root_cause, "disk_pressure")
            self.assertGreaterEqual(incident.priority, 50)

    def test_planner_only_uses_allowlist(self):
        with tempfile.TemporaryDirectory() as td:
            db = Database(str(Path(td) / "test.db")); planner = ActionPlanner(db)
            incident = IncidentCandidate("node-1", "container_failure", .9, 7, 70, "failed", "node-1:container_failure", [MetricLike("container.app.running")])
            host = {"name": "node-1", "allowed_actions": []}
            self.assertIsNone(planner.choose(incident, host))
            host["allowed_actions"] = ["restart_container:app"]
            self.assertEqual(planner.choose(incident, host), "restart_container:app")


class MetricLike:
    def __init__(self, metric): self.metric = metric


if __name__ == "__main__": unittest.main()

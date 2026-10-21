"""
Performance & Resource Quotas Test Suite (AC-10).
Measures latency overhead and verifies Docker compose CPU/memory quotas.
"""

import unittest
import yaml
import time
import asyncio
import os
from services.model_gateway.client import ModelGatewayClient


class TestPerformanceLimits(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        compose_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../infrastructure/compose/docker-compose.yml")
        )
        with open(compose_path, "r") as f:
            cls.compose = yaml.safe_load(f)

    def test_container_resource_limits_configured(self):
        """Validates that all services specify hard CPU and memory resource limits."""
        services = self.compose.get("services", {})
        for svc_name, svc_cfg in services.items():
            limits = svc_cfg.get("deploy", {}).get("resources", {}).get("limits", {})
            self.assertIn("cpus", limits, f"Service '{svc_name}' missing CPU quota")
            self.assertIn("memory", limits, f"Service '{svc_name}' missing memory quota")

    async def test_inference_latency_overhead(self):
        """AC-10: Guardrail and Model Gateway latency must be measured and within threshold."""
        client = ModelGatewayClient()
        start = time.perf_counter()
        resp = await client.infer("Benchmark prompt to evaluate inference latency overhead.")
        duration_ms = (time.perf_counter() - start) * 1000.0

        self.assertIsNotNone(resp.output_text)
        # Mock provider latency overhead must be under 100ms
        self.assertLess(duration_ms, 100.0)


if __name__ == "__main__":
    unittest.main()

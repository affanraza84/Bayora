"""
Performance & Latency Benchmark Test Suite (Phase 3 Requirement 6).
Measures repeated iterations of the mock inference pipeline and validates P95 and Median latencies.
"""

import unittest
import asyncio
from services.control_plane.routers.performance import run_benchmark
from services.control_plane.auth.jwt import SecurityContext


class TestInferenceBenchmark(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_pipeline_benchmark_execution(self):
        ctx = SecurityContext(
            user_id="bench-runner",
            tenant_id="tenant-alpha",
            role="platform_admin",
        )
        # Execute 10 iterations (40 evaluated test cases)
        report = await run_benchmark(iterations=10, current_user=ctx)

        self.assertEqual(report.benchmark_type, "SYNTHETIC_MOCK_PIPELINE")
        self.assertEqual(report.sample_size, 40)
        self.assertEqual(report.successful_requests, 40)
        self.assertEqual(report.failed_requests, 0)
        self.assertGreater(report.median_latency_ms, 0.0)
        self.assertGreaterEqual(report.p95_latency_ms, report.median_latency_ms)
        self.assertIn("DISCLAIMER", report.disclaimer)
        self.assertIn("worker_cpus", report.resource_limits_applied)


if __name__ == "__main__":
    unittest.main()

"""
Live Docker Container Isolation Test Suite (Phase 3 Requirement 4).
Executes live TCP connectivity probes, filesystem read-only checks,
and socket mount tests directly inside the running Docker Compose containers.
"""

import unittest
import subprocess
import json


def is_docker_running() -> bool:
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return res.returncode == 0
    except Exception:
        return False


def is_container_up(name: str) -> bool:
    try:
        res = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return res.returncode == 0 and "true" in res.stdout.lower()
    except Exception:
        return False


@unittest.skipUnless(
    is_docker_running() and is_container_up("bayora-worker-red"),
    "Live Docker containers not running; skipping live container execution assertions",
)
class TestLiveDockerIsolation(unittest.TestCase):
    def test_live_red_to_blue_network_probe_dropped(self):
        """Live Invariant: Red worker cannot resolve or connect to Blue worker."""
        cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            (
                "import socket, sys\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.settimeout(2.0)\n"
                "try:\n"
                "    s.connect(('bayora-worker-blue', 8002))\n"
                "    print('CONNECTED_UNEXPECTEDLY')\n"
                "    sys.exit(1)\n"
                "except Exception as e:\n"
                "    print(f'PROBE_BLOCKED: {e}')\n"
                "    sys.exit(0)\n"
            )
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("PROBE_BLOCKED", res.stdout)

    def test_live_worker_to_database_blocked(self):
        """Live Invariant: Worker containers cannot connect directly to PostgreSQL."""
        cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            (
                "import socket, sys\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.settimeout(2.0)\n"
                "try:\n"
                "    s.connect(('bayora-database', 5432))\n"
                "    print('CONNECTED_TO_DB_UNEXPECTEDLY')\n"
                "    sys.exit(1)\n"
                "except Exception as e:\n"
                "    print(f'DB_ACCESS_BLOCKED: {e}')\n"
                "    sys.exit(0)\n"
            )
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("DB_ACCESS_BLOCKED", res.stdout)

    def test_live_worker_docker_socket_not_exposed(self):
        """Live Invariant: /var/run/docker.sock does not exist inside worker containers."""
        cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            "import os; exists = os.path.exists('/var/run/docker.sock'); print('EXISTS:', exists); exit(1 if exists else 0)"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("EXISTS: False", res.stdout)

    def test_live_worker_read_only_root_filesystem(self):
        """Live Invariant: Worker container root filesystem is mounted read_only."""
        cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            (
                "try:\n"
                "    with open('/root_test_write.txt', 'w') as f: f.write('bad')\n"
                "    exit(1)\n"
                "except OSError as e:\n"
                "    print('READ_ONLY_ENFORCED:', e)\n"
                "    exit(0)\n"
            )
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Read-only file system", res.stdout)

    def test_live_blue_cannot_read_red_artifacts(self):
        """Live Invariant: Blue worker has no access to /artifacts/red volume."""
        cmd = [
            "docker", "exec", "bayora-worker-blue", "python", "-c",
            "import os; exists = os.path.exists('/artifacts/red'); print('EXISTS:', exists); exit(1 if exists else 0)"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("EXISTS: False", res.stdout)

    def test_live_model_gateway_isolated_from_red(self):
        """Live Invariant: Red worker cannot directly access model-gateway without Evaluator mediation."""
        cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            (
                "import socket, sys\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.settimeout(2.0)\n"
                "try:\n"
                "    s.connect(('bayora-model-gateway', 8003))\n"
                "    sys.exit(1)\n"
                "except Exception as e:\n"
                "    print(f'MODEL_GATEWAY_ISOLATED: {e}')\n"
                "    sys.exit(0)\n"
            )
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("MODEL_GATEWAY_ISOLATED", res.stdout)


if __name__ == "__main__":
    unittest.main()

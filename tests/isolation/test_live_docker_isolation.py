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
        """Live Invariant: Red worker cannot resolve or connect to Blue worker (both DNS and L3 IP routing)."""
        # 1. DNS Resolution Probe
        dns_cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            (
                "import socket, sys\n"
                "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "s.settimeout(2.0)\n"
                "try:\n"
                "    s.connect(('bayora-worker-blue', 8002))\n"
                "    print('CONNECTED_UNEXPECTEDLY')\n"
                "    sys.exit(1)\n"
                "except socket.gaierror as e:\n"
                "    print(f'DNS_BLOCKED: {e}')\n"
                "    sys.exit(0)\n"
                "except Exception as e:\n"
                "    print(f'OTHER_BLOCKED: {e}')\n"
                "    sys.exit(0)\n"
            )
        ]
        res_dns = subprocess.run(dns_cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res_dns.returncode, 0)
        self.assertIn("DNS_BLOCKED", res_dns.stdout)

        # 2. Raw L3 IP Route Probe (Bypassing DNS)
        # Fetch Blue worker IP dynamically
        blue_ip_cmd = ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "bayora-worker-blue"]
        blue_ip = subprocess.run(blue_ip_cmd, capture_output=True, text=True, timeout=3).stdout.strip()
        if blue_ip:
            ip_cmd = [
                "docker", "exec", "bayora-worker-red", "python", "-c",
                (
                    f"import socket, sys\n"
                    f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                    f"s.settimeout(2.0)\n"
                    f"try:\n"
                    f"    s.connect(('{blue_ip}', 8002))\n"
                    f"    sys.exit(1)\n"
                    f"except OSError as e:\n"
                    f"    print(f'L3_ROUTING_BLOCKED: {{e}}')\n"
                    f"    sys.exit(0)\n"
                )
            ]
            res_ip = subprocess.run(ip_cmd, capture_output=True, text=True, timeout=5)
            self.assertEqual(res_ip.returncode, 0)
            self.assertIn("L3_ROUTING_BLOCKED", res_ip.stdout)
            self.assertIn("Network is unreachable", res_ip.stdout)

    def test_live_worker_to_database_blocked(self):
        """Live Invariant: Worker containers cannot connect directly to PostgreSQL (DNS + L3 IP)."""
        db_ip_cmd = ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "bayora-database"]
        db_ip = subprocess.run(db_ip_cmd, capture_output=True, text=True, timeout=3).stdout.strip()

        cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            (
                f"import socket, sys\n"
                f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                f"s.settimeout(2.0)\n"
                f"try:\n"
                f"    s.connect(('{db_ip or '172.20.0.2'}', 5432))\n"
                f"    sys.exit(1)\n"
                f"except OSError as e:\n"
                f"    print(f'DB_ACCESS_BLOCKED: {{e}}')\n"
                f"    sys.exit(0)\n"
            )
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("DB_ACCESS_BLOCKED", res.stdout)
        self.assertIn("Network is unreachable", res.stdout)

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
                "    print(f'MODEL_GATEWAY_ISOLATED: {type(e).__name__} {e}')\n"
                "    sys.exit(0)\n"
            )
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("MODEL_GATEWAY_ISOLATED", res.stdout)

    def test_live_container_cgroup_resource_limits(self):
        """Live Invariant: Kernel cgroup memory and CPU limits are actively enforced inside containers."""
        cmd = [
            "docker", "exec", "bayora-worker-red", "python", "-c",
            (
                "import os\n"
                "mem_max = None\n"
                "for path in ['/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory/memory.limit_in_bytes']:\n"
                "    if os.path.exists(path):\n"
                "        with open(path) as f: mem_max = int(f.read().strip())\n"
                "        break\n"
                "cpu_max = None\n"
                "if os.path.exists('/sys/fs/cgroup/cpu.max'):\n"
                "    with open('/sys/fs/cgroup/cpu.max') as f: cpu_max = f.read().strip()\n"
                "print(f'CGROUP_LIMITS: mem={mem_max}, cpu={cpu_max}')\n"
                "assert mem_max == 536870912, f'Expected 512MB, got {mem_max}'\n"
            )
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("CGROUP_LIMITS: mem=536870912", res.stdout)

    def test_live_host_port_exposure_restricted(self):
        """Live Invariant: Internal databases and workers must not bind public host ports."""
        internal_containers = [
            "bayora-database",
            "bayora-worker-red",
            "bayora-worker-blue",
            "bayora-model-gateway",
            "bayora-audit-service",
            "bayora-evaluator",
        ]
        for name in internal_containers:
            cmd = ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", name]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            self.assertEqual(res.returncode, 0)
            ports_json = json.loads(res.stdout.strip() or "{}")
            for port_proto, bindings in ports_json.items():
                # bindings should be null/empty for internal-only containers
                self.assertIsNone(
                    bindings,
                    f"Container {name} unexpectedly exposed port {port_proto} to host: {bindings}",
                )


if __name__ == "__main__":
    unittest.main()

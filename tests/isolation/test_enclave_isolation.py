"""
Enclave Isolation & Configuration Assertion Test Suite
Validates network isolation invariants, internal bridge flags, read-only roots,
and absence of Docker socket mounts (AC-03, AC-04, AC-08).
"""

import unittest
import yaml
import os


class TestEnclaveIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compose_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../infrastructure/compose/docker-compose.yml")
        )
        with open(compose_path, "r") as f:
            cls.compose = yaml.safe_load(f)

    def test_docker_socket_not_mounted(self):
        """Invariant: Under no circumstances should docker.sock be mounted into containers."""
        services = self.compose.get("services", {})
        for svc_name, svc_cfg in services.items():
            volumes = svc_cfg.get("volumes", [])
            for vol in volumes:
                self.assertNotIn(
                    "docker.sock",
                    str(vol),
                    f"Violation! Service '{svc_name}' mounts docker socket: {vol}",
                )

    def test_worker_enclave_network_separation(self):
        """Invariant: worker-red and worker-blue must be in strictly segregated internal networks."""
        services = self.compose.get("services", {})
        networks = self.compose.get("networks", {})

        # Verify internal bridge networks
        self.assertTrue(networks.get("red-net", {}).get("internal", False))
        self.assertTrue(networks.get("blue-net", {}).get("internal", False))

        red_nets = services.get("worker-red-team", {}).get("networks", [])
        blue_nets = services.get("worker-blue-team", {}).get("networks", [])
        db_nets = services.get("database", {}).get("networks", [])

        # Red worker has no route to blue-net or control-net
        self.assertIn("red-net", red_nets)
        self.assertNotIn("blue-net", red_nets)
        self.assertNotIn("control-net", red_nets)

        # Blue worker has no route to red-net or control-net
        self.assertIn("blue-net", blue_nets)
        self.assertNotIn("red-net", blue_nets)
        self.assertNotIn("control-net", blue_nets)

        # Database is strictly in control-net
        self.assertIn("control-net", db_nets)
        self.assertNotIn("red-net", db_nets)
        self.assertNotIn("blue-net", db_nets)

    def test_worker_containers_read_only_root(self):
        """Invariant: Worker containers must have read_only filesystem roots."""
        services = self.compose.get("services", {})
        red_ro = services.get("worker-red-team", {}).get("read_only", False)
        blue_ro = services.get("worker-blue-team", {}).get("read_only", False)
        self.assertTrue(red_ro, "worker-red-team must have read_only: true")
        self.assertTrue(blue_ro, "worker-blue-team must have read_only: true")


if __name__ == "__main__":
    unittest.main()

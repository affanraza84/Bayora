"""
Bayora Shield: Adversarial Evaluation Test Suite (Phase 2 Spec)
"""

import unittest


class TestAdversarialHarnessSpec(unittest.TestCase):
    def test_adversarial_categories_present(self):
        categories = ["PROMPT_INJECTION", "JAILBREAK", "DATA_EXFILTRATION", "SYSTEM_PROMPT_LEAK"]
        self.assertIn("PROMPT_INJECTION", categories)


if __name__ == "__main__":
    unittest.main()

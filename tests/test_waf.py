import unittest
from src.waf import WAFEngine, WAFConfig, Request


class TestWAFEngine(unittest.TestCase):

    def setUp(self):
        self.config = WAFConfig()
        self.waf = WAFEngine(self.config)

    # 1️⃣ Baseline: Normal request → ALLOW
    def test_allow_normal_request(self):
        request = Request(
            source="1.1.1.1",
            endpoint="/home",
            payload=""
        )

        decision, reasons, score = self.waf.analyze(request)

        self.assertEqual(decision, "ALLOW")
        self.assertEqual(score, 0)
        self.assertEqual(reasons, [])

    # 2️⃣ High request rate → LOG
    def test_log_high_request_rate(self):
        config = WAFConfig(max_requests=2)
        waf = WAFEngine(config)

        for _ in range(3):
            request = Request(
                source="2.2.2.2",
                endpoint="/login",
                payload=""
            )
            decision, reasons, score = waf.analyze(request)

        self.assertEqual(decision, "LOG")
        self.assertIn("High request rate", reasons)
        self.assertGreaterEqual(score, 2)

    # 3️⃣ Severe anomaly → BLOCK
    def test_block_large_payload_on_sensitive_endpoint(self):
        request = Request(
            source="3.3.3.3",
            endpoint="/admin",
            payload="X" * 1000
        )

        decision, reasons, score = self.waf.analyze(request)

        self.assertEqual(decision, "BLOCK")
        self.assertIn("Large payload", reasons)
        self.assertIn("Sensitive endpoint access", reasons)
        self.assertGreaterEqual(score, 4)

    # 4️⃣ False positive protection → ALLOW or LOG (not BLOCK)
    def test_false_positive_protection(self):
        request = Request(
            source="4.4.4.4",
            endpoint="/profile",
            payload="bio=hello"
        )

        decision, reasons, score = self.waf.analyze(request)

        self.assertNotEqual(decision, "BLOCK")
        self.assertLess(score, 4)


if __name__ == "__main__":
    unittest.main()
